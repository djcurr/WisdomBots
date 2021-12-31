module server

go 1.17

replace modules/licensing => ./modules/licensing

require (
	github.com/go-sql-driver/mysql v1.6.0
	github.com/gorilla/mux v1.8.0
	github.com/pelletier/go-toml v1.9.4
	modules/licensing v0.0.0-00010101000000-000000000000
)
