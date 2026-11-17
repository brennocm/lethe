package checks

// titles are the short operator-facing names of the checks (spec §9), in pt-BR and en-US
// (spec §16.6). Notifications, the TUI and the GUI use them.
var titles = map[string][2]string{
	"NET-001":  {"Tráfego fora do túnel", "Traffic outside the tunnel"},
	"NET-002":  {"Vazamento bloqueado pelo guarda", "Leak blocked by the guard"},
	"NET-003":  {"IPv6 fora do túnel", "IPv6 outside the tunnel"},
	"NET-004":  {"Rota efetiva fora do túnel", "Effective route outside the tunnel"},
	"NET-005":  {"Mudança de rota", "Route change"},
	"NET-006":  {"Interface nova ou link up", "New interface or link up"},
	"NET-007":  {"Mudança de rede Wi-Fi", "Wi-Fi network change"},
	"NET-008":  {"MAC real em uso", "Real MAC in use"},
	"NET-009":  {"Broadcast na LAN com identificadores", "LAN broadcast with identifiers"},
	"NET-010":  {"Socket na interface física", "Socket on the physical interface"},
	"NET-011":  {"IP de saída inesperado", "Unexpected exit IP"},
	"NET-012":  {"STUN/WebRTC fora do túnel", "STUN/WebRTC outside the tunnel"},
	"NET-013":  {"Checagem de conectividade presa à interface", "Interface-bound connectivity check"},
	"NET-014":  {"DHCP envia o hostname", "DHCP sends the hostname"},
	"DNS-001":  {"DNS fora do túnel", "DNS outside the tunnel"},
	"DNS-002":  {"Resolvedor do provedor configurado", "Provider resolver configured"},
	"DNS-003":  {"Resolvedor em link físico", "Resolver on a physical link"},
	"DNS-004":  {"Configuração de DNS alterada", "DNS configuration changed"},
	"TUN-001":  {"Túnel ausente ou caído", "Tunnel missing or down"},
	"TUN-002":  {"Handshake WireGuard velho", "Stale WireGuard handshake"},
	"TUN-003":  {"Tor sem circuito", "Tor without a circuit"},
	"TUN-004":  {"Kill switch alterado", "Kill switch changed"},
	"TUN-005":  {"Split tunneling ativo", "Split tunneling active"},
	"TUN-006":  {"Endpoint inesperado", "Unexpected endpoint"},
	"TUN-007":  {"Firewall legado invisível", "Invisible legacy firewall"},
	"TUN-008":  {"Transporte plugável não suportado", "Unsupported pluggable transport"},
	"HOST-001": {"Processo da lista de negação", "Deny-listed process"},
	"HOST-002": {"Câmera ou microfone em uso", "Camera or microphone in use"},
	"HOST-003": {"Compartilhamento de tela ou acesso remoto", "Screen sharing or remote access"},
	"HOST-004": {"Hostname real", "Real hostname"},
	"HOST-005": {"Fuso ou idioma fora do perfil", "Timezone or locale outside the profile"},
	"HOST-006": {"Disco ou swap sem cifra", "Unencrypted disk or swap"},
	"HOST-007": {"Sincronização de horário", "Time synchronization"},
	"HOST-008": {"Rede Wi-Fi conhecida com autoconnect", "Known Wi-Fi with autoconnect"},
	"HOST-009": {"Serviço de geolocalização ativo", "Geolocation service active"},
	"PER-001":  {"Persona incoerente", "Incoherent persona"},
	"PER-002":  {"Configuração de navegador", "Browser configuration"},
	"PER-003":  {"Perfil pessoal do navegador", "Personal browser profile"},
	"SELF-001": {"Sensor parado", "Sensor stopped"},
	"SELF-002": {"Perda de pacotes na captura", "Capture packet loss"},
	"SELF-003": {"Agente ou GUI desconectados", "Agent or GUI disconnected"},
	"SELF-004": {"Selftest desatualizado", "Selftest out of date"},
	"SELF-005": {"Relógio alterado", "Clock changed"},
	"SELF-006": {"Tentativas de passphrase", "Passphrase attempts"},
}

// Title is the short name of check id in lang ("en-US" or anything else = pt-BR).
func Title(id, lang string) string {
	t, ok := titles[id]
	if !ok {
		return id
	}
	if lang == "en-US" || lang == "en" {
		return t[1]
	}
	return t[0]
}
