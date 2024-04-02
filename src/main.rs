
struct Words {
    swears: Vec<String>,
    common_passwords: Vec<String>,
    forbidden_usernames: Vec<String>,
    breached_passwords: Vec<String>,
}

const BCRYPT_COST: u32 = 12;

struct Session {
    username: String,
    logged_in: bool
}

/// Read some lines of a file
#[derive(serde::Serialize, serde::Deserialize)]
struct MyConfig {
    pwddbpath: String,
    swearspath: String,
    commonpasswordpath: String,
    usernamespath: String,
    breachedpasswordpath: String,
}

// Default Config
impl ::std::default::Default for MyConfig {
    fn default() -> Self {
        Self {
            breachedpasswordpath: "./breachedpasswords.txt".into(),
            swearspath: "./forbidden-words.txt".into(),
            commonpasswordpath: "./commonpasswords.txt".into(),
            pwddbpath: "./pwd.db".into(),
            usernamespath: "./forbidden-usernames.txt".into(),
        }
    }
}

fn validate_username_selection(uname: &str, words: &Words) -> bool {
    let username = uname.to_string().to_ascii_lowercase();
    // Check lengths
    if username.len() < 1 {
        println!("Username too short - must be at least 1 character");
        return false;
    }

    if username.len() > 30 {
        println!("Username too long - must be at most 30 characters");
        return false;
    }

        // Restrict charset
    let limited_charset = regex::Regex::new(r"^[a-zA-Z0-9_]*$").unwrap();
    if !limited_charset.is_match(&username){
        println!("Username must be alphanumeric, with dots, dashes and underscores allowed");
        return false;
    }
    
    // Check for forbidden usernames
    for use_i in [true, false] {
        let mut username = username.clone();
        username = numbers_to_letters(username, use_i);
        remove_whitespace(&mut username);
        for word in &words.forbidden_usernames {
            
            if  edit_distance::edit_distance(username.as_str(), word.to_ascii_lowercase().as_str()) < 2 {
                println!("{}", word);
                println!("Username is invalid - contains a forbidden word/username");
                return false;
            }
        }

        for word in &words.swears {
            if  username.contains(word.to_ascii_lowercase().as_str()) {
                println!("Username is invalid - contains a forbidden word/username");
                return false;
            }
        }
    }



    return true
}

fn numbers_to_letters(username: String, use_i: bool) -> String {
    let mut username = username.to_string();
    username = username.replace('0', "o");

    if use_i {
        username = username.replace('1', "I");
    }
    else {
        username = username.replace('1', "L");
    }

    username = username.replace('2', "Z");
    username = username.replace('3', "E");
    username =  username.replace('4', "A");
    username = username.replace('5', "S");
    username = username.replace('6', "G");
    username = username.replace('7', "T");
    username = username.replace('8', "B");
    username = username.replace('9', "g");
    username.make_ascii_lowercase();
    username
}

fn is_ascii_or_unicode(s: &str) -> bool {
    for c in s.chars() {
        if c.is_ascii(){
            if c.is_ascii_graphic() || c == ' ' {
                // only allow printable ascii characters and spaces
                continue;
            }
            else {
                return false;
            }
        }
        else {
            // allow unicode characters
            continue;
        }
    }
    true
}

fn validate_password_selection(password: &str, words: &Words) -> bool {
    let mut password = password.to_string();
    remove_whitespace(&mut password);

    if password.len() < 8 {
        println!("Password too short - must be at least 8 characters");
        return false;
    }

    if password.len() > 256 {
        println!("Password too long - must be at most 256 characters");
        return false;
    }

    if !is_ascii_or_unicode(password.as_str())  {
        println!("Password includes invalid character(s)");
        return false;
    }
    
    let mut last_char = ' ';
    let mut char_in_sequence = 0;
    let mut last_num = 0;
    let mut num_in_sequence = 0;
    for c in password.chars() {
        if c == last_char {
            char_in_sequence += 1;
        }
        else {
            char_in_sequence = 0;
        }

        if char_in_sequence > 3 {
            println!("Password must not use repeated characters, or numbers in sequence");
            return false;
        }

        if c.is_numeric() {
            if c as u8 == last_num + 1 {
                num_in_sequence += 1;
            }
            else {
                num_in_sequence = 0;
            }
            if num_in_sequence >= 3 {
                println!("Password must not use repeated characters, or numbers in sequence");
                return false;
            }
            last_num = c as u8;
        }
        last_char = c;
    }

    for pwd in &words.common_passwords {
        let pwd = pwd.to_string().to_ascii_lowercase().trim().to_string();
        //Lictenshine distance of <3 helps us know if they've just added an ! to the end of a common password, or something similar
        if edit_distance::edit_distance(pwd.as_str(), password.as_str()) < 2 {
            println!("Password is too close to a weak/breached password - please choose a different password");
            return false;
        }
    }

    for pwd in &words.breached_passwords {
        let pwd = pwd.to_string().to_ascii_lowercase().trim().to_string();
        if edit_distance::edit_distance(pwd.as_str(), password.as_str()) < 2 {
            println!("Password is too close to a weak/breached password - please choose a different password");
            return false;
        }
    }

    return true;
}

fn create_user(connection: &rusqlite::Connection , username: &str, password: &str) -> bool {
    let username = username.to_string().to_ascii_lowercase();
    
    let hash = bcrypt::hash_with_result(password, BCRYPT_COST).unwrap();
    match connection.execute(
        "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
        [username, hash.to_string()],
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn change_password(connection: &rusqlite::Connection , username: &str, password: &str) -> bool {
    let username = username.to_string().to_ascii_lowercase();
    
    let hash = bcrypt::hash_with_result(password, BCRYPT_COST).unwrap();
    match connection.execute(
        "UPDATE users SET password_hash = ?2 WHERE username = ?1;",
        [username, hash.to_string()],
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn check_password(connection: &rusqlite::Connection, username: &str, password: &str) -> bool {
    let username = username.to_string().to_ascii_lowercase();

    let row: String = connection.query_row(
        "SELECT password_hash FROM users WHERE username = ?1;",
        [username],
        |row| row.get(0)
    ).unwrap();
    bcrypt::verify(password, &row).unwrap()
}

fn username_in_db(connection: &rusqlite::Connection, username: &str) -> bool {
    let username = username.to_string().to_ascii_lowercase();

    let row: Result<String, rusqlite::Error> = connection.query_row(
        "SELECT username FROM users WHERE username = ?1;",
        [username],
        |row| row.get(0)
    );
    match row {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn remove_whitespace(s: &mut String) {
    s.retain(|c| !c.is_whitespace());
}

fn main() {
    let mut logged_in = false;
    let mut session_username = String::new();
    let mut should_exit = false;
    let args: MyConfig = confy::load_path("./config").unwrap();
    let connection = rusqlite::Connection::open(args.pwddbpath).unwrap();

    let bad_words = std::fs::read_to_string(args.swearspath).expect("Failed to read swears file");
    let common_passwords = std::fs::read_to_string(args.commonpasswordpath).expect("Failed to read common passwords file");
    let forbidden_usernames = std::fs::read_to_string(args.usernamespath).expect("Failed to read forbidden usernames file");
    let breached_passwords = std::fs::read_to_string(args.breachedpasswordpath).expect("Failed to read breached passwords file");
    let words = Words {
        swears: bad_words.lines().map(|s| s.to_string()).collect(),
        common_passwords: common_passwords.lines().map(|s| s.to_string()).collect(),
        forbidden_usernames: forbidden_usernames.lines().map(|s| s.to_string()).collect(),
        breached_passwords: breached_passwords.lines().map(|s| s.to_string()).collect(),
    };

    connection.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );",
        [],
    ).unwrap();

    println!("Welcome to PWA (Password Authentication)");
    
    loop {
        if should_exit {
            break;
        }
        if logged_in {
            logged_in = logged_in_state(&connection, &mut should_exit, &words, &session_username);
            if !logged_in {
                session_username = "".to_string();
            }
        }
        else {
            let new_session: Session = logged_out_state(&connection, &mut should_exit, &words);
            logged_in = new_session.logged_in;
            session_username = new_session.username;
        }
    }

     println!("Goodbye!");

}

fn logged_in_state(connection: &rusqlite::Connection, exit: &mut bool, words: &Words, session_username: &String) -> bool {
        println!("------------------------------------");
        println!("Please select an option: ");
        println!("1. Change Password");
        println!("2. Logout");
        println!("3. Exit");
        let mut user_input = String::new();
        std::io::stdin().read_line(&mut user_input).unwrap();
        remove_whitespace(&mut user_input);
        match user_input.as_str() {
            "1" => {
                println!("Passwords must be at least 8 characters long, and must not be too similar to a common password, or a password that has been breached");
                let mut password;
                loop {
                    println!("Enter new password:");
                    password = String::new();
                    std::io::stdin().read_line(&mut password).unwrap();
                    remove_whitespace(&mut password);

                    if !validate_password_selection(&password, &words) {
                        println!("Invalid password - Please try again");
                        continue;
                    }

                    println!("Confirm password:");
                    let mut confirm_password = String::new();
                    std::io::stdin().read_line(&mut confirm_password).unwrap();
                    remove_whitespace(&mut confirm_password);

                    if password != confirm_password {
                        println!("Passwords do not match - Please try again");
                        continue;
                    }


                    break
                }
                change_password(&connection, &session_username, &password);
                println!("Password changed successfully");
            },
            "2" => {
                println!("Logging out");
                return false;
            },
            "3" => {
                *exit = true;
                return false
            },
            _ => {
                println!("Invalid selection - Please try again: {}", user_input);
            }
        }
    true
}

fn logged_out_state(connection: &rusqlite::Connection, exit: &mut bool, words: &Words) -> Session {
        println!("------------------------------------");
        println!("Please select an option: ");
        println!("1. Create User");
        println!("2. Login");
        println!("3. Exit");
        let mut user_input = String::new();
        std::io::stdin().read_line(&mut user_input).unwrap();
        remove_whitespace(&mut user_input);

        match user_input.as_str() {
            "1" => {
                let mut username;
                loop {
                    println!("Enter username (or empty to exit):");
                    username = String::new();
                    std::io::stdin().read_line(&mut username).unwrap(); 

                    remove_whitespace(&mut username);
                    username = username.to_ascii_lowercase();

                    if username.as_str() == "" {
                        return Session {
                            username: "".to_string(),
                            logged_in: false}
                    }

                    if !validate_username_selection(&username, &words) {
                        println!("Invalid username - Please try again");
                        continue;
                    }


                    if username_in_db(&connection, &username) {
                        println!("Username already exists");
                        continue;
                    }
                    break;
                }

                let mut password;
                loop {
                    println!("Enter password:");
                    password = String::new();
                    std::io::stdin().read_line(&mut password).unwrap();
                    remove_whitespace(&mut password);

                    if !validate_password_selection(&password, &words) {
                        println!("Invalid password - Please try again");
                        continue;
                    }

                    println!("Confirm password:");
                    let mut confirm_password = String::new();
                    std::io::stdin().read_line(&mut confirm_password).unwrap();
                    remove_whitespace(&mut confirm_password);

                    if password != confirm_password {
                        println!("Passwords do not match - Please try again");
                        continue;
                    }

                    break
                }

            
                let success = create_user(&connection, &username, &password);
                if !success {
                    println!("Failed to create user - Database error");
                    return Session {
                        username: "".to_string(),
                        logged_in: false
                    }
                }

                println!("User created successfully - Welcome new user: {}", username);
                return Session {
                    username: username,
                    logged_in: true
                }
            },
            "2" => {
                let mut failed_attempts = 0;
                loop {
                    if failed_attempts >= 5 {
                        println!("Too many failed login attempts - Exiting");
                        *exit = true;
                        return Session {
                            username: "".to_string(),
                            logged_in: false}
                    }

                    println!("Enter username (or empty to exit):");
                    let mut username_buf = String::new();
                    std::io::stdin().read_line(&mut username_buf).unwrap();
                    remove_whitespace(&mut username_buf);
                    username_buf = username_buf.to_ascii_lowercase();

                    if username_buf == "" {
                        return Session {
                            username: "".to_string(),
                            logged_in: false}
                    }
                    
                    println!("Enter password:");
                    let mut password_buf = String::new();
                    std::io::stdin().read_line(&mut password_buf).unwrap();
                    remove_whitespace(&mut password_buf);

                    if username_in_db(&connection, &username_buf) && check_password(&connection, &username_buf, &password_buf) {
                        println!("Login successful - Welcome back {}", username_buf);
                        println!("If you see this message, you've logged in, but we ran out of funding to do anything else");
                        return Session {
                            username: username_buf.to_string(),
                            logged_in: true}
                    }
                    else {
                        failed_attempts += 1;
                        println!("Login failed - Incorrect username or password");
                    }
                }
            },
            "3" => {
                *exit = true;
                return Session {
                    username: "".to_string(),
                    logged_in: false}
            },
            _ => {
                println!("Invalid selection - Please try again: {}", user_input);
            }
        }
        Session {
            username: "".to_string(),
            logged_in: false}
    
}