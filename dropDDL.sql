ALTER TABLE USER_TICTUNNEL DROP FOREIGN KEY FK_USER_TICTUNNEL_User_ID
ALTER TABLE USER_TICTUNNEL DROP FOREIGN KEY FK_USER_TICTUNNEL_tunnels_ID
DROP TABLE USER
DROP TABLE TICTUNNEL
DROP TABLE USER_TICTUNNEL
DELETE FROM SEQUENCE WHERE SEQ_NAME = 'SEQ_GEN'