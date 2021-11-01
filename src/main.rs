use std::fs;

use walkdir::{DirEntry, WalkDir};

fn is_hidden(entry: &DirEntry) -> bool {
    entry.path().to_string_lossy().starts_with("/etc/nixos/nixpkgs/.git")
}

fn main() { 
    let walker = WalkDir::new("/etc/nixos/nixpkgs").into_iter();
    for entry in walker.filter_entry(|e| !is_hidden(e)) {
        let entry = entry.unwrap();
        if entry.metadata().unwrap().is_dir() {
            continue;
        }
        if entry.path().to_string_lossy() == "/etc/nixos/nixpkgs/pkgs/desktops/gnome/extensions/extensions.json" {
            println!("skipping: {}", entry.path().display());
            continue;
        }
        if entry.path().to_string_lossy() == "/etc/nixos/nixpkgs/pkgs/tools/security/polkit-gnome/polkit-gnome-authentication-agent-1.desktop" {
            println!("skipping: {}", entry.path().display());
            continue;
        }
        if entry.path().to_string_lossy() == "/etc/nixos/nixpkgs/pkgs/development/haskell-modules/hackage-packages.nix" {
            println!("skipping: {}", entry.path().display());
            continue;
        }

        // probably still vulnerable to grapheme attacks?
        match fs::read_to_string(entry.path()) {
            Ok(contents) => if !contents.is_ascii() {
                let mut forbidden_chars = contents.chars().filter(|char| {
                    !char.is_ascii() && ![
                        // no offense intended.
                        '’', '”', '“', '→', '…', '—', 'ö', 'è', 'í', 'µ', '©',
                        '↑', '↓', 'ë', 'é', '–', '‘', '®', 'ø', 'λ', '§', 'É',
                        'à', 'Ö', '└', '─', '│', '├', '❯', '😃', 'á', 'ñ', 'Ł',
                        '‑', 'ƒ', '🐀', '😀', 'ő', 'ú', 'ō', 'ô', '«', '»', '²',
                        '‐', 'ó', 'ù', 'ì', 'ü', 'ä', '™', '•', '≤', 'Λ', 'ř', 
                        '−', '✨', 'Č', '≥', 'å', 'ç', 'Å', 'ê', 'є', 'α','β',
                        'δ', '‹', '›', '💩', 'æ', 'Ü', '¯', 'ツ', '¯', 'ℓ', '×',
                        '❌', '✅', 'π', '🍕', '╵', '·', '┤', '┘', '┴', '┐', '┬', '┌',
                        'ÿ', '╵', '⚡', '🐈', '🙂', 'π', 'ʃ', 'ʊ', 'ə', 'ಠ', 'š', 
                        '⟧', '⟦', 'î', 'ł', '☺', '一', '下', 'क', 'ˈ', 'ʌ', 'ɪ',
                        '圍', '棋', '囲', '碁', '바', '둑', '╭', '┈', '╯', 'ɜ', 'ː',
                        '𐀀', '┼', 'ń', 'ž', 'ß', 'ć', 'ï', 'Ș', 'ß', '貓', 
                        'ă', 'ě', 'č', 'ž', 'ễ', 'Ç', 'ı', 'ş', 'ï', 'ò', 'ą', 
                        'Ø', 'ż', 'и', 'к', 'Á', 'ð', 'Ž', 'Д', '№',
                        '⊗', 'Θ', 'ć', 'Š', 'ę', 'ꓵ', 'ꓭ', 'ꓢ', 'ꓱ', 'ꓷ', 'ꓶ',
                        'ꓲ', '🧀', 'ɔ', 'ʒ', 'ʁ', '余', '音', '五', '目', '並', 'べ',
                        '年', '糕', '小', '豆', '汤', 'А', 'П', 'Р', '📦',
                        '汉', '字', '转', '拼', 'Н', 'т', 'К', 'з', 'н', 'е', 'ц', 'о', 'в',
                        '⚠', '⚿', '漢', '▸', '⚫',
                        'И', 'м', 'ч', 'с', 'й', 'л', 'б', 'д', 'я', 'г', 'І', 'м', 'ь',
                        'ш', '免', '登', '录', '、', '免', '，', '免', '费', '载', '上',
                        '的', '曲', '谱', '站' ,'插', '画', '批', '量', '载', '器',
                        '🍱', '↔', 'Π', '検', '定', '↔', 'ω', '∘', 'ω', 'М', '検', '定', 'ニ',
                        'コ', 'ニ', '動', '°',

                        // we have rtl text e.g. in /etc/nixos/nixpkgs/pkgs/data/fonts/vazir-fonts/default.nix
                        // rtl itself is fine the risk is characters that look e.g. ascii or explicit reading-order
                        // changing-characters (which are detected by Github)
                        
                        'у', 'х', 'а', 'р', // maintainer names - interesting
                        'С', ' ', // this looks weird
                        '\u{202f}', // NARROW NO-BREAK SPACE
                        '\u{feff}', // ZERO WIDTH NO-BREAK SPACE
                        '\u{308}', // COMBINING DIAERESIS
                        '\u{ad}', // SOFT HYPHEN
                        '\u{fe0f}', // VARIATION SELECTOR-16
                        '\u{2002}', // EN SPACE
                        '\u{200b}', // ZERO WIDTH SPACE - well yeah but no
                        '\u{92}', // PRIVATE USE TWO* - what is this?
                        '\u{303}', // COMBINING TILDE
                        '\u{2009}', // THIN SPACE
                        '�',
                        '🚀',
                    ].contains(char)
                }).collect::<String>();

                // My RTL editor support is so great that I did this:
                // randomly ordered characters - no offense intended.
                forbidden_chars = forbidden_chars.chars().filter(|char| {
                    !"فونتقشبلپمفارسیگصحمیزمهد".chars().any(|c| &c == char)
                }).collect::<String>();

                if forbidden_chars.len() != 0 {
                    println!("utf-8: {}", entry.path().display());
                    println!("{}", forbidden_chars);
                    println!("{:#?}", forbidden_chars);
                }
            },
            Err(_) => {
                println!("invalid utf8: {}", entry.path().display());
            },
        }
    }

    println!("example: {}", "а".escape_unicode());
}
