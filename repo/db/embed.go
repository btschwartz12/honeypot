package db

import (
	_ "embed"
)

//go:embed sql/cowrie/schema.sql
var CowrieSchema []byte

//go:embed sql/schema.sql
var MainSchema []byte
