# go-htmx-base

This project serves as a solid foundation for your Go-based full-stack projects. You can use it as a starting point and customize it according to your needs.

## Motive

As a full-stack developer in a small team, I often found myself grappling with the challenges of using different languages or frameworks for the frontend and backend. This led to duplicated logics and types across both layers, making maintenance cumbersome. Managing dependencies and configuration files for both ends of the project only added to the complexity. Furthermore, dealing with state on both the frontend and backend can be cumbersome. If you relate to these challenges, go-htmx-base provides a starting point to free yourself from the complexities of the JavaScript/TypeScript dilemma.

## Tech Stacks

This project is using:

- [Go](https://go.dev/) and [Echo](https://echo.labstack.com/) as backend.
- [sqlc](https://docs.sqlc.dev/en/stable/index.html) and [goose](https://github.com/pressly/goose) for database integration.
- [postgres](https://www.postgresql.org/) and [redis](https://redis.io/) for database and caching.
- [templ](https://github.com/a-h/templ) and [htmx](https://htmx.org/docs) for server-side rendering frontend.

## Features

This base backend offers the following key features:

- Code generation from SQL with [sqlc](https://docs.sqlc.dev/en/stable/index.html).
- Database migration capabilities using [goose](https://github.com/pressly/goose).
- Integration of PostgreSQL and Redis with Docker.
- Web server powered by [Echo](https://echo.labstack.com/).
- Session-based authentication.
- Role-based permissions for users.
- Support for Cron Jobs.
- Comprehensive logging system.

## Dependencies

Please make sure you have the following dependencies installed:

- [Git](https://github.com/git-guides/install-git)
- [Go](https://go.dev/doc/install)
- [Docker](https://docs.docker.com/engine/install/) (required for running databases in a development environment)
- [Make](https://www.gnu.org/software/make/) (used for predefined commands in [Makefile](/Makefile))
- [goose](#goose)
- [tailwindCSS](#tailwindCSS)

## Installation and Setup

To get started with the go-htmx-base project, follow these steps:

1. Install all the [dependencies](#dependencies).

2. Clone the project repository from GitHub and install the required packages:

   ```bash
   git clone https://github.com/JK-1117/go-htmx-base.git
   cd go-htmx-base
   go mod tidy
   ```

3. Configure the project to match your requirements. Refer to the [Congifurations Section](#configurations).

4. Start the database services with Docker:

   ```bash
   docker compose up
   ```

5. Build and run the application:

   ```bash
   make server
   ```

6. Access the application in your web browser at `http://localhost:8080`.

## Configurations

Here are some optional configurations that you may want to customize for your project:

- [Makefile](/Makefile)

  - Configure the Postgres URL, change the user, password, and DB name.
  - Modify the main folder and the binary name to match your app's name.

- [.env](/.env)

  To configure your project properly, you need to create a `.env` file. This file will contain important environment variables required for your project's operation. Here are the necessary variables to include in your `.env` file:

  - `PORT`: Set this variable to define the port on which your server will run.
  - `DOMAIN`: Specify the domain for your production server.
  - `REDIS_URL`: This variable should hold the URL for connecting to your Redis instance.
  - `DB_URL`: Set this variable to contain the URL for connecting to your PostgreSQL database.
  - `COOKIE_HASHKEY`: Provide a strong hash key for authenticating cookie values using HMAC (for [more information](https://github.com/gorilla/securecookie#examples)).
  - `COOKIE_BLOCKKEY`: Define a block key for encrypting cookie values (for [more information](https://github.com/gorilla/securecookie#examples)).

  Here's an example of how your `.env` file should look:

  ```env
  # .env

  PORT=8080
  DOMAIN=localhost

  REDIS_URL=redis://localhost:6379/0
  DB_URL=postgres://go_htmx:DevPassword@localhost:5432/go_htmx?sslmode=disable

  COOKIE_HASHKEY=your_cookie_hash_key_here
  COOKIE_BLOCKKEY=your_cookie_block_key_here
  ```

- [docker-compose.yaml](/docker-compose.yaml)

  - Configure environment variables and ports for the services.

- Module name

  - Replace "github.com/JK-1117/go-htmx-base" with your module name.

- Session Cookie Name
  - You can change the session ID's cookie name by modifying the SESSIONCOOKIE constant in [session.go](/internal/router/session.go)

## Hot Reloading

For hot reloading, consider using [Air](https://github.com/cosmtrek/air). A sample configuration file [.air.toml](/.air.toml) is provided for you to customize based on your requirements.

## goose

For Windows user, you should download the [executable release](https://github.com/pressly/goose/releases) and place it inside [./bin](#bin/) folder. You may refer to [pressly/goose](https://github.com/pressly/goose) for installation instruction on different operating system.

## tailwindCSS

As we're not utilizing Node.js, we've opted for the standalone CLI for tailwindCSS. Refer to [Standalone CLI: Use Tailwind CSS without Node.js](https://tailwindcss.com/blog/standalone-cli) for details on the standalone executable. You should download the executable and place it inside [./bin](#bin/) folder.

## Contributing

Contributions to this repository are welcome. If you encounter any issues or have suggestions for improvements, please open an issue or submit a pull request on the GitHub repository.

## License

This project is licensed under the [MIT License](https://opensource.org/license/mit/).

## Acknowledgements

This project was inspired by an [Amazing Free Course](https://www.youtube.com/watch?v=un6ZyFkqFKo&t=32565s) by [freeCodeCamp.org](https://www.youtube.com/@freecodecamp) and [bootdotdev](https://www.youtube.com/@bootdotdev). Check out their amazing content to learn more. Special thanks to the developers and all the open-source contributors whose libraries and frameworks have been used in this project. Icons and images used are generated using [Fooocus](https://github.com/lllyasviel/Fooocus) or get from [Icons8](https://icons8.com).

## Contact

For any questions or inquiries, please contact the project maintainer at `chun11197@gmail.com`.
