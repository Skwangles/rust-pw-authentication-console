# Rust PW Authentication system

Built a simple console application which uses Rusqlite to story usernames and password hashes - with salts.
If this were a proper production system the database would of course be less accessible


## Usage
Create your own:
 - [forbidden-words.txt](https://www.cs.cmu.edu/~biglou/resources/bad-words.txt) <- looks for substring
 - [commonpasswords.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt) <- looks for the Levenshtein distance between these and passwords, include breached passwords in this file too
 - [forbidden-usernames.txt](https://github.com/shouldbee/reserved-usernames/blob/master/reserved-usernames.txt) <- looks for Levenshtein distance between this and username  
*Note: The system converts numbers beforehand to closest letters, so do not worry about things like `ro0t`.*

Update your `config` file with file paths  

Make sure the project is built, and all the required dependencies are installed: 
`cargo build`  

Run the actual code: 
`cargo run`  

*Note: with `cargo run` the filepaths use the top most directory as `./` (i.e. not in src, or target)*  

---

Alternatively, run the released exe with the required files alongside


