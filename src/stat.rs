use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::f64;
use std::hash::Hash;

/// A HashMap of `f64`-valued buckets whose chi-squared goodness of fit can be calculated.
pub struct Histogram<T>(pub HashMap<T, f64>);

/// Possible errors when trying to calculate goodness-of-fit values for a `Histogram`
#[derive(Debug, Eq, PartialEq)]
pub enum HistogramError {
    BucketNotFound,
    HistogramMismatch,
}

impl Histogram<char> {
    pub fn english() -> Self {
        Histogram(
            [
                ('e', 0.12702),
                ('t', 0.09056),
                ('a', 0.08167),
                ('o', 0.07507),
                ('i', 0.06966),
                ('n', 0.06749),
                ('s', 0.06327),
                ('h', 0.06094),
                ('r', 0.05987),
                ('d', 0.04253),
                ('l', 0.04025),
                ('c', 0.02782),
                ('u', 0.02758),
                ('m', 0.02406),
                ('w', 0.02360),
                ('f', 0.02228),
                ('g', 0.02015),
                ('y', 0.01974),
                ('p', 0.01929),
                ('b', 0.01492),
                ('v', 0.00978),
                ('k', 0.00772),
                ('j', 0.00153),
                ('x', 0.00150),
                ('q', 0.00095),
                ('z', 0.00074),
                ('\u{0}', f64::MAX),
            ]
            .iter()
            .cloned()
            .collect::<HashMap<char, f64>>(),
        )
    }
}

impl<T> Histogram<T>
where
    T: Hash + Eq,
{
    /// Calculate the chi-squared goodness-of-fit metric between this and a baseline histogram.
    /// Returns a single dimensionless value, with 0 being an exact match.
    pub fn chisq(&self, baseline: &Histogram<T>) -> Result<f64, HistogramError> {
        self.0
            .iter()
            .map(|(item, freq)| match baseline.0.get(item) {
                Some(b_freq) => Ok((freq - b_freq) * (freq - b_freq) / (freq + b_freq)),
                None => Err(HistogramError::BucketNotFound),
            })
            .collect::<Result<Vec<f64>, HistogramError>>()
            .map(|v| v.iter().sum())
    }

    /// Normalize this histogram, making all values sum to 1.
    pub fn normalize(&mut self) {
        let len = self.0.iter().len();
        self.0.iter_mut().for_each(|(_, n)| *n = *n / (len as f64));
    }
}

/// Create a histogram from a source corpus, counting each occurrence of a value iterated over,
/// and with each value used to key the map.
impl<V, K> From<V> for Histogram<K>
where
    K: Hash + Eq,
    V: Iterator<Item = K>,
{
    fn from(list: V) -> Self {
        Histogram(list.into_iter().fold(HashMap::new(), |mut acc, i| {
            match acc.entry(i) {
                Entry::Occupied(mut e) => {
                    e.insert(*(e.get()) + 1f64);
                } // increase count by 1.0
                Entry::Vacant(e) => {
                    e.insert(1f64);
                } // store 1.0 if not found
            };
            acc
        }))
    }
}

/// Look through the iterator, scoring each, and using `cmp` to find the best.
///
/// This function repeatedly calls `score_fn` on each element in `r`. It then calls `cmp` with
/// the last, best item found. If `cmp` returns true, it keeps the new element, else it keeps
/// the last one.
///
/// If `score_fn` returns `None`, the last, best score is kept. If `score_fn` only ever returns
/// `None`, this function returns `None`.
///
/// ```
/// use arse::stat::find_best_in;
/// use std::usize;
///
/// let words = ["hello", "goodbye", "hola", "adios", "!!!"];
/// let letter = 'o';
/// let most = find_best_in(
///     words.into_iter(),
///     |w| Some(w.chars().filter(|c| *c == letter).count()),
///     usize::gt
/// );
/// assert_eq!(most.unwrap(), &"goodbye");
/// ```
pub fn find_best_in<I, F, G, T, S>(r: I, score_fn: F, cmp: G) -> Option<T>
where
    I: Iterator<Item = T>,
    F: Fn(&T) -> Option<S>,
    G: Fn(&S, &S) -> bool,
{
    r.fold(None, |best_score: Option<(T, S)>, test_val: T| {
        let score = score_fn(&test_val);

        // the following code is a bit contorted because we can't bind by-move and by-ref at
        // the same time if the first match arm were to read:
        //  (Some(score), Some((_, best_score_val))) => {
        //          ^- by-move            ^- by-ref
        // So instead we match against a reference, destructure into a new binding, and unwrap
        // the original value to move it since we know it's valid.
        match (&score, &best_score) {
            (Some(inner), Some((_, best_score_val))) => {
                if cmp(inner, best_score_val) {
                    Some((test_val, score.unwrap()))
                } else {
                    best_score
                }
            }
            // we haven't found a reasonable score yet, so this is the best
            (Some(_), None) => Some((test_val, score.unwrap())),
            // We couldn't score this one, so take whatever we've had before (even if it's None)
            (None, _) => best_score,
        }
    })
    .map(|(t, _)| t)
}
