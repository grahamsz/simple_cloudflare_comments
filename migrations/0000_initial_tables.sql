-- Migration number: 0000 	 2022-11-20T14:31:29.364Z
CREATE TABLE users (
	user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    auth_provider text not NULL,
    auth_provider_id text not null,
    picture_url text not null,
	first_name TEXT NOT NULL,
	last_name TEXT NOT NULL,
    is_admin integer default 0
    
);

CREATE TABLE threads (
    thread_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE
);

CREATE TABLE comments (
    comment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    comment text not null,
    sanitized_comment text,
    thread_id int not null,
    user_id int,
    timestamp int,
    in_response_to_comment_id int,

    FOREIGN KEY (thread_id) 
      REFERENCES threads (thread_id) 
         ON DELETE CASCADE 
         ON UPDATE NO ACTION,


    FOREIGN KEY (user_id) 
      REFERENCES users (user_id) 
         ON DELETE CASCADE 
         ON UPDATE NO ACTION,



    FOREIGN KEY (in_response_to_comment_id) 
      REFERENCES comments (comment_id) 
         ON DELETE CASCADE 
         ON UPDATE NO ACTION

);