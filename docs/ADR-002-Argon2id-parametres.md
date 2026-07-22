Architecture Decision Report 002
The following ADR refers to a chosen parametres of password hashing algorithm Argon2id. Our group decided on the following:
Memory: 64 MiB
*Basis*
It's considered a balansed, still very safe memory cost.

Iterations: 3
*Basis*
1-4 is common, however one should higher the number of iterations if memory cost is low.

Parallelism: 1
*Basis*
It's considered a safe minimum. There is no reason to use more than 1 core of CPU in this simple project.
