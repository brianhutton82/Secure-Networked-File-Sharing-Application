@echo off
javac -cp ".;bcprov-jdk18on-172.jar" *.java
java -cp ".;bcprov-jdk18on-172.jar" RunGroupServer

