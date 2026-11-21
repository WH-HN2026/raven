package db

// ListOrder is the requested column and direction for a paginated list.
// The caller must map Column to a fixed expression before using it in SQL.
type ListOrder struct {
	Column    string
	Direction string
}

func (o ListOrder) SQLDirection() string {
	if o.Direction == "desc" {
		return "DESC"
	}
	return "ASC"
}

// Key is a bound parameter used by sqlc queries with fixed ORDER BY cases.
func (o ListOrder) Key() string {
	if o.Column == "" {
		return ""
	}
	if o.Direction == "desc" {
		return o.Column + "_desc"
	}
	return o.Column + "_asc"
}
