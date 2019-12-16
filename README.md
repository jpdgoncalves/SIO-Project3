# SIO-Project2
Segundo Projeto de SIO

## How to run the code
After cloning the repository and creating a virtual environment with all the requirements:
- register a user with the following command. Make sure to have the citizenship card connected to your pc. Then follow the instructions that will be prompted. A <username>.user file should be produced.
> python3 src/authentication.py register
- Open 2 consoles
- In one of them run:
> source venv/bin/activate

> python3 src/server.py
- In the other one run:
> source venv/bin/activate

> python3 src/client.py <name_of_file>
