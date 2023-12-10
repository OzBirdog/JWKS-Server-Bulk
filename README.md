JWKS Server Project 3
CSCE 3550.001
Oz Birdett (oeb0010)
12-10-2023

Description: The following respository contains the files, "server.py" and "test.py", for the JWKS Server Project 3. 
As well as screenshots showing the results of both the test suite and the gradebot being run with the JWKS server. 
Both files are written in Python and the "server.py" file utilizes SQLite 3 for the database.The "server.py" file 
is a server that provides public keys with unique identifeirs for veryifing JSON Web tokens and stores them in a database. 
The keys are generated using RSA, have an expiration, and authentication endpoint. The testSuite.py file has three test cases 
to run against the JWKS Server to check the test coverage. The screenshot for the gradebot is "Project 3 Gradebot.PNG" and for the test suite is "Project 3 Testsuite.PNG".

Execution:

For test coverage:

Run server.py in one terminal
Run test.py in another terminal
Check results in terminal of test.py

(It should be noted that "test.py" can be run on its own without "server.py" and will show the results in the terminal.)

For test client:

Run server.py
Run gradebot in terminal with "start gradebot project 3"
Check results pop up window
