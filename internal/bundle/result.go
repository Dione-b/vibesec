package bundle

type Result struct {
	Scripts    []string `json:"scripts,omitempty"`
	Libraries  []string `json:"libraries,omitempty"`
	Routes     []string `json:"routes,omitempty"`
	Endpoints  []string `json:"endpoints,omitempty"`
	AdminPages []string `json:"admin_pages,omitempty"`
	Secrets    []string `json:"secrets,omitempty"`
}

func (r *Result) RouteCount() int {
	if r == nil {
		return 0
	}
	return len(r.Routes)
}

func (r *Result) EndpointCount() int {
	if r == nil {
		return 0
	}
	return len(r.Endpoints)
}

func (r *Result) AdminCount() int {
	if r == nil {
		return 0
	}
	return len(r.AdminPages)
}
