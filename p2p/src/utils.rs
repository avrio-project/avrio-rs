use std::collections::HashMap;

/// this calculates the most common string in a list
pub fn get_mode(v: Vec<String>) -> String {
    let mut map = HashMap::new();

    for num in v {
        let count = map.entry(num).or_insert(0);
        *count += 1;
    }

    return (**map.iter().max_by_key(|(_, v)| *v).unwrap().0).to_string();
}
