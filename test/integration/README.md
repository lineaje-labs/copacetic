# README #

Readme for Copacetic integration tests

The integration tests internally use [testcontainers-go](https://github.com/testcontainers/testcontainers-go)

It requires the following.

- Docker client to be installed locally
- Connection to the Internet to download container image and packages
- [copa-lineaje-scanner](https://github.com/lineaje-labs/copa-lineaje-scanner)

## Steps

- Run tests from the root directory by calling the integration make target
```
make integration
```

## Appendix

- testcontainers-go uses [ryuk](https://hub.docker.com/r/testcontainers/ryuk) to perform cleanup of any running containers at the end of the test
- [dockertest](https://github.com/ory/dockertest) was also looked at to implement the integration tests.
It was not selected as it did not support reuse of containers or parallel runs.

### Approaches Considered

#### Approach A

1. Pull base images (Alpine, Debian, Ubuntu, RPM-based) using testcontainers-go.  
2. Run the `copa` command by passing the image name and the input report (in Lineaje format) as arguments – this generates the output JSON file.  
3. Compare the generated JSON output against the expected output for validation.

#### Approach B

1. Pull a Docker-in-Docker (DinD) image via testcontainers-go.  
2. Install `copacetic` and `copa-lineaje-scanner` inside the DinD container.  
3. Copy the necessary inputs into the DinD container.
4. Pull base images inside the DinD environment.  
5. Run the `copa` command within DinD with appropriate arguments.  
6. Validate results internally within the DinD container.

While both approaches aim to verify integration end-to-end, **Approach B** introduces additional complexity due to the use of Docker-in-Docker, which is known to be non-trivial and potentially fragile in testing scenarios.

As a result, we are proceeding with **Approach A**, which is more straightforward and avoids unnecessary overhead while effectively meeting the integration testing goals.