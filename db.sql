CREATE SCHEMA idm;

create table idm.token_status (
    id int not null primary key,
    value varchar(32) not null
);

create table idm.user_status(
  id int not null primary key,
  value varchar(32) not null
);

create table idm.role(
    id int not null primary key,
    name varchar(32) not null,
    description varchar(128) not null,
    precedence int not null
);

create table idm.user(
    id int not null primary key AUTO_INCREMENT,
    email varchar(32) not null unique,
    user_status_id int not null,
    salt char(8) not null,
    hashed_password char(88) not null,
    foreign key (user_status_id) references idm.user_status(id)
        on update cascade on delete  restrict
);

create table idm.refresh_token(
    id int NOT NULL PRIMARY KEY AUTO_INCREMENT,
    token	CHAR(36)	NOT NULL UNIQUE,
    user_id	INT	NOT NULL,
    token_status_id	INT	NOT NULL,
    expire_time	TIMESTAMP	NOT NULL,
    max_life_time	TIMESTAMP	NOT NULL,
    FOREIGN KEY (user_id) REFERENCES idm.user (id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (token_status_id) REFERENCES idm.token_status (id)
        ON UPDATE CASCADE ON DELETE RESTRICT
);

create table idm.user_role(
    user_id	INT	NOT NULL,
    role_id	INT	NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES idm.user (id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES idm.role (id)
        ON UPDATE CASCADE ON DELETE RESTRICT

);