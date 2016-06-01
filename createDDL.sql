CREATE TABLE USER (ID VARCHAR(255) NOT NULL, EMAILADDRESS VARCHAR(255), NAME VARCHAR(255), PASSWORD VARCHAR(255), USERNAME VARCHAR(255) NOT NULL UNIQUE, PRIMARY KEY (ID))
CREATE TABLE TICTUNNEL (ID VARCHAR(255) NOT NULL, ADMINSTATE VARCHAR(10) NOT NULL, CREATIONDATE DATETIME NOT NULL, HEARTBEATINTERVAL INTEGER NOT NULL, IPV4POP LONGBLOB, IPV6ENDPOINT VARCHAR(255) NOT NULL UNIQUE, IPV6POP VARCHAR(255) NOT NULL, MTU INTEGER NOT NULL, PASSWORD VARCHAR(30) NOT NULL, POPNAME VARCHAR(255) NOT NULL, PREFIXLENGTH INTEGER NOT NULL, TUNNELID VARCHAR(255) NOT NULL UNIQUE, TUNNELNAME VARCHAR(255) NOT NULL, TYPE VARCHAR(10) NOT NULL, USERSTATE VARCHAR(10) NOT NULL, PRIMARY KEY (ID))
CREATE TABLE USER_TICTUNNEL (User_ID VARCHAR(255) NOT NULL, tunnels_ID VARCHAR(255) NOT NULL, PRIMARY KEY (User_ID, tunnels_ID))
ALTER TABLE USER_TICTUNNEL ADD CONSTRAINT FK_USER_TICTUNNEL_User_ID FOREIGN KEY (User_ID) REFERENCES USER (ID)
ALTER TABLE USER_TICTUNNEL ADD CONSTRAINT FK_USER_TICTUNNEL_tunnels_ID FOREIGN KEY (tunnels_ID) REFERENCES TICTUNNEL (ID)
CREATE TABLE SEQUENCE (SEQ_NAME VARCHAR(50) NOT NULL, SEQ_COUNT DECIMAL(38), PRIMARY KEY (SEQ_NAME))
INSERT INTO SEQUENCE(SEQ_NAME, SEQ_COUNT) values ('SEQ_GEN', 0)
