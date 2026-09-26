use crate::collections::TryCow;
use crate::error::{Result, bail};
use crate::{Atom, StringPool, prelude::*};
use alloc::sync::Arc;
use core::borrow::Borrow;
use core::hash::Hash;
use semver::Version;
use serde_derive::{Deserialize, Serialize};
use wasmparser::WasmFeatures;
use wasmparser::names::{
    ComponentName, ComponentNameKind, pad_canonical_version, split_canonical_version,
};

/// A semver-aware map for imports/exports of a component.
///
/// This data structure is used when looking up the names of imports/exports of
/// a component to enable semver-compatible matching of lookups. This will
/// enable lookups of `a:b/c@0.2.0` to match entries defined as `a:b/c@0.2.1`
/// which is currently considered a key feature of WASI's compatibility story.
///
/// On the outside this looks like a map of `K` to `V`.
#[derive(Serialize, Deserialize, Debug)]
pub struct NameMap<K, V>
where
    K: TryClone + Hash + Eq + Ord,
{
    /// A map of keys to the value that they define.
    ///
    /// Note that this map is "exact" where the name here is the exact name that
    /// was specified when the `insert` was called. This doesn't have any
    /// semver-mangling or anything like that.
    ///
    /// This map is always consulted first during lookups.
    definitions: TryIndexMap<K, V>,

    /// An auxiliary map tracking semver-compatible names. This is a map from
    /// "semver compatible alternate name" to a name present in `definitions`
    /// and the semver version it was registered at.
    ///
    /// An example map would be:
    ///
    /// ```text
    /// {
    ///     "a:b/c@0.2": ("a:b/c@0.2.1", 0.2.1),
    ///     "a:b/c@2": ("a:b/c@2.0.0+abc", 2.0.0+abc),
    ///     "a:b/c@0.0.1": ("a:b/c@0.0.1+abc", 0.0.1+abc),
    ///     "a:b/d@1": ("a:b/d@1", 1.0.0),
    /// }
    /// ```
    ///
    /// As names are inserted into `definitions` each name may have up to one
    /// semver-compatible name with extra numbers/info chopped off which is
    /// inserted into this map. This map is the lookup table from `@0.2` to
    /// `@0.2.x` where `x` is what was inserted manually.
    ///
    /// The `Version` here is tracked to ensure that when multiple versions on
    /// one track are defined that only the maximal version here is retained.
    /// Canonical names such as `a:b/d@1` are padded to their lowest version.
    alternate_lookups: TryIndexMap<K, (K, TryVersion)>,
}

/// A wrapper around `Version` that implements `TryClone`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct TryVersion(Arc<Version>);

impl TryFrom<Version> for TryVersion {
    type Error = OutOfMemory;

    fn try_from(value: Version) -> Result<Self, Self::Error> {
        Ok(Self(try_new::<Arc<_>>(value)?))
    }
}

impl TryClone for TryVersion {
    #[inline]
    fn try_clone(&self) -> Result<Self, OutOfMemory> {
        Ok(Self(self.0.clone()))
    }
}

impl core::ops::Deref for TryVersion {
    type Target = Version;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<Version> for TryVersion {
    #[inline]
    fn borrow(&self) -> &Version {
        &self.0
    }
}

impl serde::Serialize for TryVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for TryVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let v = Version::deserialize(deserializer)?;
        let v = try_new::<Arc<_>>(v).map_err(|oom| D::Error::custom(oom))?;
        Ok(Self(v))
    }
}

impl<K, V> TryClone for NameMap<K, V>
where
    K: TryClone + Hash + Eq + Ord,
    V: TryClone,
{
    fn try_clone(&self) -> Result<Self, OutOfMemory> {
        Ok(Self {
            definitions: self.definitions.try_clone()?,
            alternate_lookups: self.alternate_lookups.try_clone()?,
        })
    }
}

impl<K, V> NameMap<K, V>
where
    K: TryClone + Hash + Eq + Ord,
{
    /// Inserts the `name` specified into this map.
    ///
    /// The name is intern'd through the `cx` argument and shadowing is
    /// controlled by the `allow_shadowing` variable.
    ///
    /// This function will automatically insert an entry in
    /// `self.alternate_lookups` if `name` is a semver-looking name, including
    /// canonical names such as `a:b/c@0.2`.
    ///
    /// Note that this never merges `item` with a semver-compatible definition,
    /// see [`NameMap::get_or_insert_with`] for that.
    ///
    /// Returns an error if `name` isn't a valid component name, see
    /// [`validate_name`], or if `allow_shadowing` is `false` and the `name` is
    /// already present in this map (by exact match). Otherwise returns the
    /// intern'd version of `name`. Note that the definition may later be
    /// re-keyed to a higher version by [`NameMap::get_or_insert_with`], after
    /// which the returned key no longer refers to it.
    pub fn insert<I>(&mut self, name: &str, cx: &mut I, allow_shadowing: bool, item: V) -> Result<K>
    where
        I: NameMapIntern<Key = K>,
        I::BorrowedKey: Hash + Eq,
    {
        validate_name(name)?;

        // Always insert `name` and `item` as an exact definition.
        let key = cx.intern(name)?;
        if !allow_shadowing && self.definitions.contains_key(&key) {
            bail!("map entry `{name}` defined twice")
        }
        self.definitions.insert(key.try_to_owned()?, item)?;

        // If `name` is a semver-looking thing, like `a:b/c@1.0.0`, then also
        // insert an entry in the semver-compatible map under a key such as
        // `a:b/c@1`.
        //
        // This key is used during `get` later on.
        if let Some((alternate_key, version)) = semver_track(name) {
            let alternate_key = cx.intern(alternate_key)?;
            let version = TryVersion::try_from(version)?;
            if let Some((prev_key, prev_version)) = self.alternate_lookups.insert(
                alternate_key.try_clone()?,
                (key.try_clone()?, version.clone()),
            )? {
                // Prefer the latest version, so only do this if we're
                // greater than the prior version.
                if version < prev_version {
                    self.alternate_lookups
                        .insert(alternate_key, (prev_key, prev_version))?;
                }
            }
        }
        Ok(key)
    }

    /// Looks up `name` within this map, using the interning specified by
    /// `cx`.
    ///
    /// This may return a definition even if `name` wasn't exactly defined in
    /// this map, such as looking up `a:b/c@0.2.0` when the map only has
    /// `a:b/c@0.2.1` defined. Canonical names, such as `a:b/c@0.2`, return the
    /// maximal version defined on that semver track.
    pub fn get<I>(&self, name: &str, cx: &I) -> Option<&V>
    where
        I: NameMapIntern<Key = K>,
        I::Key: Borrow<I::BorrowedKey>,
        I::BorrowedKey: Hash + Eq,
    {
        let (index, _exact) = self.get_index_of(name, cx)?;
        Some(&self.definitions[index])
    }

    /// Looks up `name` the same way as [`NameMap::get`], returning the index
    /// of the definition in `self.definitions` and whether it was an exact
    /// match for `name`.
    fn get_index_of<I>(&self, name: &str, cx: &I) -> Option<(usize, bool)>
    where
        I: NameMapIntern<Key = K>,
        I::Key: Borrow<I::BorrowedKey>,
        I::BorrowedKey: Hash + Eq,
    {
        // First look up an exact match and if that's found return that. This
        // enables defining multiple versions in the map and the requested
        // version is returned if it matches exactly.
        //
        // This is skipped for canonical names, such as `a:b/c@0.2`, as those
        // always resolve to the maximal version on their semver track. Note
        // that a canonical name is itself on its own track, so an exact
        // definition is still found below if it's the maximal version.
        let is_canonical = matches!(semver_track(name), Some((track, _)) if track == name);
        if !is_canonical {
            let candidate = cx
                .lookup(name)
                .and_then(|k| self.definitions.get_index_of(&*k));
            if let Some(index) = candidate {
                return Some((index, true));
            }
        }

        // Failing that, then try to look for a semver-compatible alternative.
        // This looks up the semver track of `name`, which is `name` itself if
        // it's already canonical, and then looks to see if that was intern'd
        // in `strings`. Given all that look to see if it was defined in
        // `alternate_lookups` and finally at the end that exact key is then
        // used to look up again in `self.definitions`.
        let alternate_key = cx.lookup(canonical_name(name))?;
        let (exact_key, _version) = self.alternate_lookups.get(&alternate_key)?;
        let index = self.definitions.get_index_of(exact_key.borrow())?;
        Some((index, false))
    }

    /// Looks up `name` like [`NameMap::get`] and returns the definition found
    /// if `can_merge` returns `true` for it, and otherwise inserts `default()`
    /// like [`NameMap::insert`].
    ///
    /// This is used to merge definitions on the same semver track. If `name`
    /// resolves to a mergeable definition on its semver track, but not an
    /// exact match, and `name` is a higher version than that definition, then
    /// the definition is re-keyed to `name`. For example if `a:b/c@0.2.0` is
    /// defined then `a:b/c@0.2.3` re-keys that definition to `a:b/c@0.2.3`
    /// while `a:b/c@0.2` or `a:b/c@0.1.0` leaves it as-is.
    ///
    /// Returns an error if `name` isn't valid, see [`validate_name`], even if
    /// it would otherwise resolve to an existing definition.
    pub fn get_or_insert_with<I>(
        &mut self,
        name: &str,
        cx: &mut I,
        allow_shadowing: bool,
        can_merge: impl FnOnce(&V) -> bool,
        default: impl FnOnce() -> V,
    ) -> Result<&mut V>
    where
        I: NameMapIntern<Key = K>,
        I::Key: Borrow<I::BorrowedKey>,
        I::BorrowedKey: Hash + Eq,
    {
        validate_name(name)?;
        let index = match self.get_index_of(name, cx) {
            Some((index, exact)) if can_merge(&self.definitions[index]) => {
                if !exact {
                    self.upgrade_key(index, name, cx)?;
                }
                index
            }
            _ => {
                let key = self.insert(name, cx, allow_shadowing, default())?;
                self.definitions.get_index_of::<K>(&key).unwrap()
            }
        };
        Ok(self.definitions.get_index_mut(index).unwrap().1)
    }

    /// Re-keys the definition at `index` to `name` if `name` is a higher
    /// version on the same semver track.
    ///
    /// This requires that the definition at `index` is the maximal version on
    /// the semver track of `name` and that `name` isn't already defined.
    fn upgrade_key<I>(&mut self, index: usize, name: &str, cx: &mut I) -> Result<()>
    where
        I: NameMapIntern<Key = K>,
        I::BorrowedKey: Hash + Eq,
    {
        let Some((alternate_key, version)) = semver_track(name) else {
            return Ok(());
        };
        let alternate_key = cx.intern(alternate_key)?;
        let prev_version = match self.alternate_lookups.get(&alternate_key) {
            Some((_, prev_version)) => prev_version,
            None => return Ok(()),
        };
        if version <= **prev_version {
            return Ok(());
        }
        let key = cx.intern(name)?;
        if self
            .definitions
            .replace_index(index, key.try_clone()?)
            .is_err()
        {
            unreachable!("map entry `{name}` is already defined");
        }
        let version = TryVersion::try_from(version)?;
        self.alternate_lookups
            .insert(alternate_key, (key, version))?;
        Ok(())
    }

    /// Returns an iterator over inserted values in this map.
    ///
    /// Note that the iterator return yields intern'd keys and additionally does
    /// not do anything special with semver names and such, it only literally
    /// yields what's been inserted with [`NameMap::insert`].
    pub fn raw_iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.definitions.iter()
    }
}

impl<K, V> Default for NameMap<K, V>
where
    K: TryClone + Hash + Eq + Ord,
{
    fn default() -> NameMap<K, V> {
        NameMap {
            definitions: Default::default(),
            alternate_lookups: Default::default(),
        }
    }
}

/// A helper trait used in conjunction with [`NameMap`] to optionally intern
/// keys to non-strings.
pub trait NameMapIntern {
    /// The key that this interning context generates.
    type Key: Borrow<Self::BorrowedKey>;

    /// The borrowed version of the key type.
    type BorrowedKey: ?Sized + TryToOwned<Owned = Self::Key>;

    /// Inserts `s` into `self` and returns the intern'd key `Self::Key`.
    fn intern(&mut self, s: &str) -> Result<Self::Key, OutOfMemory>;

    /// Looks up `s` in `self` returning `Some` if it was found or `None` if
    /// it's not present.
    fn lookup<'a>(&'a self, s: &'a str) -> Option<TryCow<'a, Self::BorrowedKey>>;
}

/// For use with [`NameMap`] when no interning should happen and instead string
/// keys are copied as-is.
pub struct NameMapNoIntern;

impl NameMapIntern for NameMapNoIntern {
    type Key = TryString;
    type BorrowedKey = str;

    fn intern(&mut self, s: &str) -> Result<Self::Key, OutOfMemory> {
        TryString::try_from(s)
    }

    fn lookup<'a>(&'a self, s: &'a str) -> Option<TryCow<'a, Self::BorrowedKey>> {
        Some(TryCow::Borrowed(s))
    }
}

impl NameMapIntern for StringPool {
    type Key = Atom;
    type BorrowedKey = Atom;

    fn intern(&mut self, string: &str) -> Result<Atom, OutOfMemory> {
        self.insert(string)
    }

    fn lookup(&self, string: &str) -> Option<TryCow<'_, Atom>> {
        self.get_atom(string).map(TryCow::Owned)
    }
}

/// Determines a version-based "alternate lookup key" for the `name` specified.
///
/// Some examples are:
///
/// * `foo` => `None`
/// * `foo:bar/baz` => `None`
/// * `foo:bar/baz@1.1.2` => `Some(foo:bar/baz@1)`
/// * `foo:bar/baz@0.1.0` => `Some(foo:bar/baz@0.1)`
/// * `foo:bar/baz@0.0.1` => `Some(foo:bar/baz@0.0.1)`
/// * `foo:bar/baz@0.0.1+abc` => `Some(foo:bar/baz@0.0.1)`
/// * `foo:bar/baz@0.1.0-rc.2+abc` => `Some(foo:bar/baz@0.1.0-rc.2)`
/// * `foo:bar/baz@1` => `None`
///
/// The alternate lookup key is the canonical name of `name`, as defined by
/// [`split_canonical_version`], and is only returned if `name` has a full
/// version. This alternate lookup key is intended to serve the purpose where
/// a semver-compatible definition can be located, if one is defined, at
/// perhaps either a newer or an older version.
pub fn alternate_lookup_key(name: &str) -> Option<(&str, Version)> {
    let at = name.find('@')?;
    let version_string = &name[at + 1..];
    let (canonical, _suffix) = split_canonical_version(version_string)?;
    let version = Version::parse(version_string).ok()?;
    Some((&name[..at + 1 + canonical.len()], version))
}

/// Returns the canonical name of the semver track that `name` is on.
///
/// This is the same as [`alternate_lookup_key`] except that names without an
/// alternate lookup key are returned as-is. Some examples are:
///
/// * `foo` => `foo`
/// * `foo:bar/baz@1.1.2` => `foo:bar/baz@1`
/// * `foo:bar/baz@1` => `foo:bar/baz@1`
/// * `foo:bar/baz@0.1.0` => `foo:bar/baz@0.1`
/// * `foo:bar/baz@0.0.1+abc` => `foo:bar/baz@0.0.1`
pub fn canonical_name(name: &str) -> &str {
    match alternate_lookup_key(name) {
        Some((name, _version)) => name,
        None => name,
    }
}

/// Returns the semver track that `name` is on, along with the version of
/// `name`.
///
/// This is the same as [`alternate_lookup_key`] except that canonical names,
/// such as `a:b/c@0.2`, are on their own track and have the lowest version on
/// that track, such as `0.2.0`, see [`pad_canonical_version`].
fn semver_track(name: &str) -> Option<(&str, Version)> {
    if let Some(track) = alternate_lookup_key(name) {
        return Some(track);
    }
    let at = name.find('@')?;
    let version = pad_canonical_version(&name[at + 1..])?;
    Some((name, version))
}

/// Validates that `name` is a valid component import or export name.
///
/// In addition to the checks of [`ComponentName`], this requires that the
/// version of an interface name, if any, is either a full version, such as
/// `a:b/c@0.2.1`, or a canonical version, such as `a:b/c@0.2`. Validation of
/// interface versions is otherwise deferred by [`ComponentName`] since the
/// full version may depend on a `versionsuffix`.
fn validate_name(name: &str) -> Result<()> {
    let parsed = match ComponentName::new_with_features(name, 0, WasmFeatures::all()) {
        Ok(parsed) => parsed,
        Err(e) => bail!("invalid name `{name}`: {}", e.message()),
    };
    if let ComponentNameKind::Interface(interface) = parsed.kind() {
        if interface.version(None).is_err() && semver_track(name).is_none() {
            bail!("invalid name `{name}`: version is neither a full nor canonical version");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{NameMap, NameMapNoIntern};
    use crate::prelude::*;

    #[test]
    fn alternate_lookup_key() {
        fn alt(s: &str) -> Option<&str> {
            super::alternate_lookup_key(s).map(|(s, _)| s)
        }

        assert_eq!(alt("x"), None);
        assert_eq!(alt("x:y/z"), None);
        assert_eq!(alt("x:y/z@1.0.0"), Some("x:y/z@1"));
        assert_eq!(alt("x:y/z@1.1.0"), Some("x:y/z@1"));
        assert_eq!(alt("x:y/z@1.1.2"), Some("x:y/z@1"));
        assert_eq!(alt("x:y/z@2.1.2"), Some("x:y/z@2"));
        assert_eq!(alt("x:y/z@2.1.2+abc"), Some("x:y/z@2"));
        assert_eq!(alt("x:y/z@0.1.2"), Some("x:y/z@0.1"));
        assert_eq!(alt("x:y/z@0.1.3"), Some("x:y/z@0.1"));
        assert_eq!(alt("x:y/z@0.2.3"), Some("x:y/z@0.2"));
        assert_eq!(alt("x:y/z@0.2.3+abc"), Some("x:y/z@0.2"));
        assert_eq!(alt("x:y/z@0.0.1"), Some("x:y/z@0.0.1"));
        assert_eq!(alt("x:y/z@0.0.1+abc"), Some("x:y/z@0.0.1"));
        assert_eq!(alt("x:y/z@0.0.1-pre"), Some("x:y/z@0.0.1-pre"));
        assert_eq!(alt("x:y/z@0.1.0-pre"), Some("x:y/z@0.1.0-pre"));
        assert_eq!(alt("x:y/z@1.0.0-pre+abc"), Some("x:y/z@1.0.0-pre"));
        assert_eq!(alt("x:y/z@1"), None);
        assert_eq!(alt("x:y/z@1.2"), None);
    }

    #[test]
    fn name_map_smoke() {
        let mut map = NameMap::default();
        let mut intern = NameMapNoIntern;

        map.insert("a", &mut intern, false, 0).unwrap();
        map.insert("b", &mut intern, false, 1).unwrap();

        assert!(map.insert("a", &mut intern, false, 0).is_err());
        assert!(map.insert("a", &mut intern, true, 0).is_ok());

        assert_eq!(map.get("a", &intern), Some(&0));
        assert_eq!(map.get("b", &intern), Some(&1));
        assert_eq!(map.get("c", &intern), None);

        map.insert("a:b/c@1.0.0", &mut intern, false, 2).unwrap();
        map.insert("a:b/c@1.0.1", &mut intern, false, 3).unwrap();
        assert_eq!(map.get("a:b/c@1.0.0", &intern), Some(&2));
        assert_eq!(map.get("a:b/c@1.0.1", &intern), Some(&3));
        assert_eq!(map.get("a:b/c@1.0.2", &intern), Some(&3));
        assert_eq!(map.get("a:b/c@1.1.0", &intern), Some(&3));
    }

    #[test]
    fn canonical_name() {
        use super::canonical_name;

        assert_eq!(canonical_name("x"), "x");
        assert_eq!(canonical_name("x:y/z"), "x:y/z");
        assert_eq!(canonical_name("x:y/z@1.1.2"), "x:y/z@1");
        assert_eq!(canonical_name("x:y/z@1"), "x:y/z@1");
        assert_eq!(canonical_name("x:y/z@0.2.3+abc"), "x:y/z@0.2");
        assert_eq!(canonical_name("x:y/z@0.2"), "x:y/z@0.2");
        assert_eq!(canonical_name("x:y/z@0.0.1"), "x:y/z@0.0.1");
        assert_eq!(canonical_name("x:y/z@1.0.0-pre"), "x:y/z@1.0.0-pre");
    }

    #[test]
    fn name_map_canonical_lookup() {
        let mut map = NameMap::default();
        let mut intern = NameMapNoIntern;

        map.insert("a:b/c@1.0.0", &mut intern, false, 0).unwrap();
        map.insert("a:b/c@1.0.1", &mut intern, false, 1).unwrap();
        map.insert("a:b/d@0.2.0", &mut intern, false, 2).unwrap();
        map.insert("a:b/e@0.0.1", &mut intern, false, 3).unwrap();

        // Canonical names resolve to the maximal version on their track.
        assert_eq!(map.get("a:b/c@1", &intern), Some(&1));
        assert_eq!(map.get("a:b/d@0.2", &intern), Some(&2));

        // Full versions still prefer an exact match.
        assert_eq!(map.get("a:b/c@1.0.0", &intern), Some(&0));
        assert_eq!(map.get("a:b/c@1.0.1", &intern), Some(&1));
        assert_eq!(map.get("a:b/c@1.0.2", &intern), Some(&1));

        // Other tracks don't match.
        assert_eq!(map.get("a:b/c@2", &intern), None);
        assert_eq!(map.get("a:b/d@0.3", &intern), None);
        assert_eq!(map.get("a:b/e@0.0.1", &intern), Some(&3));
        assert_eq!(map.get("a:b/e@0.0.2", &intern), None);

        // Versions that differ only in build metadata are on the same track.
        map.insert("a:b/f@0.0.1+b", &mut intern, false, 4).unwrap();
        map.insert("a:b/f@0.0.1+a", &mut intern, false, 5).unwrap();
        assert_eq!(map.get("a:b/f@0.0.1+a", &intern), Some(&5));
        assert_eq!(map.get("a:b/f@0.0.1+b", &intern), Some(&4));
        assert_eq!(map.get("a:b/f@0.0.1+c", &intern), Some(&4));
        assert_eq!(map.get("a:b/f@0.0.1", &intern), Some(&4));
        assert_eq!(map.get("a:b/f@0.0.2", &intern), None);
    }

    #[test]
    fn name_map_insert_canonical() {
        let mut map = NameMap::default();
        let mut intern = NameMapNoIntern;

        // Canonical names are on their own track as the lowest version.
        map.insert("a:b/c@1", &mut intern, false, 0).unwrap();
        map.insert("a:b/d@0.2", &mut intern, false, 1).unwrap();
        assert_eq!(map.get("a:b/c@1", &intern), Some(&0));
        assert_eq!(map.get("a:b/c@1.2.3", &intern), Some(&0));
        assert_eq!(map.get("a:b/d@0.2", &intern), Some(&1));
        assert_eq!(map.get("a:b/d@0.2.1", &intern), Some(&1));

        // Higher full versions take over the track, even for lookups of the
        // canonical name itself.
        map.insert("a:b/c@1.0.1", &mut intern, false, 2).unwrap();
        assert_eq!(map.get("a:b/c@1", &intern), Some(&2));
        assert_eq!(map.get("a:b/c@1.0.0", &intern), Some(&2));
        assert_eq!(map.get("a:b/c@1.2.3", &intern), Some(&2));

        // Invalid names and versions are rejected.
        for name in [
            "",
            "aB",
            "foo_bar",
            "a:b",
            "a:b/c@",
            "a:b/c@0",
            "a:b/c@0.0",
            "a:b/c@01",
            "a:b/c@0.02",
            "a:b/c@1.2",
            "a:b/c@1.x",
        ] {
            let err = map.insert(name, &mut intern, false, 3).unwrap_err();
            assert!(err.to_string().contains(&format!("`{name}`")), "{err}");
            assert_eq!(map.get(name, &intern), None);
        }

        // Other kinds of names are accepted.
        for name in [
            "[constructor]a",
            "[method]a.b",
            "[static]a.b",
            "a:b/c@0.0.1",
            "a:b/c@1.0.0-pre",
            "locked-dep=<a:b/c@1.2.3>",
            "unlocked-dep=<a:b/c@{>=1.2.3}>",
            "url=<https://user@host/x>",
        ] {
            map.insert(name, &mut intern, false, 3).unwrap();
            assert_eq!(map.get(name, &intern), Some(&3));
        }
    }

    #[test]
    fn name_map_get_or_insert_with() {
        let mut map = NameMap::default();
        let mut intern = NameMapNoIntern;

        // Values of at least 10 are mergeable, and merging adds one.
        fn get_or_insert(map: &mut NameMap<TryString, u32>, name: &str, default: u32) -> u32 {
            let v = map
                .get_or_insert_with(name, &mut NameMapNoIntern, false, |v| *v >= 10, || default)
                .unwrap();
            if *v >= 10 {
                *v += 1;
            }
            *v
        }
        fn keys(map: &NameMap<TryString, u32>) -> Vec<&str> {
            map.raw_iter().map(|(k, _)| &**k).collect()
        }

        assert_eq!(get_or_insert(&mut map, "a:b/c@0.2.1", 10), 11);
        assert_eq!(keys(&map), ["a:b/c@0.2.1"]);

        // Exact, lower, and canonical names reopen the definition as-is.
        assert_eq!(get_or_insert(&mut map, "a:b/c@0.2.1", 0), 12);
        assert_eq!(get_or_insert(&mut map, "a:b/c@0.2.0", 0), 13);
        assert_eq!(get_or_insert(&mut map, "a:b/c@0.2", 0), 14);
        assert_eq!(keys(&map), ["a:b/c@0.2.1"]);

        // A higher version re-keys the definition.
        assert_eq!(get_or_insert(&mut map, "a:b/c@0.2.3", 0), 15);
        assert_eq!(keys(&map), ["a:b/c@0.2.3"]);
        assert_eq!(map.get("a:b/c@0.2", &intern), Some(&15));
        assert_eq!(map.get("a:b/c@0.2.1", &intern), Some(&15));
        assert_eq!(map.get("a:b/c@0.2.3", &intern), Some(&15));

        // Other tracks get their own definition.
        assert_eq!(get_or_insert(&mut map, "a:b/c@0.3.0", 20), 21);
        assert_eq!(get_or_insert(&mut map, "a:b/c@1", 30), 31);
        assert_eq!(get_or_insert(&mut map, "a:b/c@1.0.1", 0), 32);
        assert_eq!(keys(&map), ["a:b/c@0.2.3", "a:b/c@0.3.0", "a:b/c@1.0.1"]);

        // Definitions that can't be merged coexist with each other, except
        // for exact duplicates.
        map.insert("a:b/d@1.0.0", &mut intern, false, 0).unwrap();
        assert_eq!(get_or_insert(&mut map, "a:b/d@1.0.1", 1), 1);
        assert_eq!(keys(&map)[3..], ["a:b/d@1.0.0", "a:b/d@1.0.1"]);
        assert_eq!(map.get("a:b/d@1.0.0", &intern), Some(&0));
        assert_eq!(map.get("a:b/d@1", &intern), Some(&1));
        assert!(
            map.get_or_insert_with("a:b/d@1.0.0", &mut intern, false, |_| false, || 2)
                .is_err()
        );
    }
}
