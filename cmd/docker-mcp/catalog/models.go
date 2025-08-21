package catalog

type Registry struct {
	Registry map[string]Tile `yaml:"registry"`
}

type Tile struct {
	Description string                 `yaml:"description"`
	ReadmeURL   string                 `yaml:"readme"`
	ToolsURL    string                 `yaml:"toolsUrl"`
	Title       string                 `yaml:"title,omitempty"`
	Type        string                 `yaml:"type,omitempty"`
	Transport   map[string]interface{} `yaml:"transport,omitempty"`
	OAuth       map[string]interface{} `yaml:"oauth,omitempty"`
	Tools       []map[string]string    `yaml:"tools,omitempty"`
	Icon        string                 `yaml:"icon,omitempty"`
	Upstream    string                 `yaml:"upstream,omitempty"`
}
