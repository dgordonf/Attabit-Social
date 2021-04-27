
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