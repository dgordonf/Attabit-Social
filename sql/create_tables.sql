
CREATE TABLE meadow.posts (
    post_id INT AUTO_INCREMENT PRIMARY KEY,
    camp_id INT,
    user_id INT,
    creation_time     DATETIME DEFAULT   CURRENT_TIMESTAMP,
    last_update_time  DATETIME ON UPDATE CURRENT_TIMESTAMP,
    post_text    	VARCHAR(10000) NULL,
    post_img_url    VARCHAR(200) NULL,
    opacity   		DECIMAL(5,4) DEFAULT 1.0000
    
);


CREATE TABLE meadow.users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64),
    email VARCHAR(120),
    password_hash VARCHAR(128),
    first_name VARCHAR(64) NULL,
    last_name VARCHAR(64) NULL,
    creation_time     DATETIME DEFAULT   CURRENT_TIMESTAMP,
    last_update_time  DATETIME ON UPDATE CURRENT_TIMESTAMP,
    up_points   	INT
    
);

CREATE TABLE meadow.camp_directory (
    record_id INT AUTO_INCREMENT PRIMARY KEY,
    camp_id INT,
    user_id INT,
    added_time     DATETIME DEFAULT   CURRENT_TIMESTAMP
);


CREATE TABLE meadow.post_votes (
    vote_id INT AUTO_INCREMENT PRIMARY KEY,
    camp_id INT,
    user_id INT,
    record_id INT,
    value DECIMAL(5, 3),
    added_time     DATETIME DEFAULT   CURRENT_TIMESTAMP
);

CREATE TABLE meadow.media (
    photo_id INT AUTO_INCREMENT PRIMARY KEY,
    post_id INT,
    photo_url VARCHAR(64) NULL,
    added_time     DATETIME DEFAULT   CURRENT_TIMESTAMP
);

CREATE TABLE meadow.camps (
    camp_id INT AUTO_INCREMENT PRIMARY KEY,
    camp_hash VARCHAR(25) NULL,
    camp_name VARCHAR(10000) NULL,
    camp_type INT,
    creation_time     DATETIME DEFAULT   CURRENT_TIMESTAMP,
    last_update_time  DATETIME ON UPDATE CURRENT_TIMESTAMP,
    camp_img_url    VARCHAR(200) NULL
);

CREATE TABLE meadow.follows (
    follow_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    following INT,
    follow_value INT,
    creation_time     DATETIME DEFAULT   CURRENT_TIMESTAMP,
    last_update_time  DATETIME ON UPDATE CURRENT_TIMESTAMP
   
);

CREATE TABLE meadow.tokens (
    token_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    token VARCHAR(100),
    type INT,
    used INT,
    creation_time     DATETIME DEFAULT   CURRENT_TIMESTAMP,
    last_update_time  DATETIME ON UPDATE CURRENT_TIMESTAMP
  
);


CREATE TABLE meadow.notifications (
    notification_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    triggered_by_user_id INT,
    event_type_id INT,
    reference_post_id INT,
    seen INT DEFAULT 0,
    seen_time  DATETIME, 
    creation_time     DATETIME DEFAULT   CURRENT_TIMESTAMP,
    last_update_time  DATETIME ON UPDATE CURRENT_TIMESTAMP
  
);


