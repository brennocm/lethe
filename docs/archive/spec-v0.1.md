# lethe

# OPSECMON — Especificação Técnica v1 (Linux)

> Monitor local de OpSec para operações de investigação/CTI: detecta, registra e reage a vazamentos de IP, DNS e identidade durante toda a operação.

| Campo | Valor |
|---|---|
| Versão do documento | 0.1 (rascunho) |
| Data | 2026-11-15 |
| Plataforma v1 | Linux (x86_64 e arm64) |
| Nome | `opsecmon` (provisório) |
| Status | Em definição |

---

## Sumário

1. [Visão geral](#1-visão-geral)
2. [Modelo de ameaça](#2-modelo-de-ameaça)
3. [Princípios de design](#3-princípios-de-design)
4. [Escopo da v1 e requisitos de sistema](#4-escopo-da-v1-e-requisitos-de-sistema)
5. [Arquitetura](#5-arquitetura)
6. [Ciclo de vida de uma operação](#6-ciclo-de-vida-de-uma-operação)
7. [Descoberta automática do ambiente](#7-descoberta-automática-do-ambiente)
8. [Catálogo de checks](#8-catálogo-de-checks)
9. [Severidade, estados e respostas](#9-severidade-estados-e-respostas)
10. [Modo guarda (nftables)](#10-modo-guarda-nftables)
11. [Linha de base (baseline)](#11-linha-de-base-baseline)
12. [Perfil de operação](#12-perfil-de-operação)
13. [Logs, relatório e cadeia de custódia](#13-logs-relatório-e-cadeia-de-custódia)
14. [CLI](#14-cli)
15. [GUI e TUI](#15-gui-e-tui)
16. [IPC entre daemon e interfaces](#16-ipc-entre-daemon-e-interfaces)
17. [Autoteste (selftest)](#17-autoteste-selftest)
18. [Segurança da própria ferramenta](#18-segurança-da-própria-ferramenta)
19. [Stack técnica](#19-stack-técnica)
20. [Requisitos não funcionais](#20-requisitos-não-funcionais)
21. [Critérios de aceitação](#21-critérios-de-aceitação)
22. [Limitações conhecidas](#22-limitações-conhecidas)
23. [Roadmap](#23-roadmap)
24. [Questões em aberto](#24-questões-em-aberto)

---

## 1. Visão geral

### 1.1 Problema

O operador trabalha atrás de VPN e/ou Tor, mas o anonimato depende de dezenas de detalhes que falham em silêncio: o túnel cai, o kill switch do cliente VPN não cobre todas as interfaces, o IPv6 sai por fora, o DNS volta para o resolvedor do provedor, um app se liga direto à interface física, a máquina entra numa rede Wi-Fi nova, um cliente de sincronização se conecta com a conta pessoal. Na maioria dos casos o operador só fica sabendo depois, se ficar.

### 1.2 Solução

O `opsecmon` é uma ferramenta **instalada na hora**, em cima do ambiente que o operador já usa. Ela não substitui o cliente VPN nem o Tor. Ela:

1. **Descobre** o ambiente (túnel, endpoints, interfaces físicas, DNS).
2. **Verifica** antes de começar (preflight).
3. **Monitora** continuamente durante a operação.
4. **Reage** automaticamente a eventos críticos (alerta forte e, opcionalmente, bloqueio).
5. **Registra** tudo num log cifrado, encadeado e assinado, que serve de registro operacional e de cadeia de custódia.

### 1.3 Regra central

> **Na interface física, só pode sair tráfego destinado ao endpoint do túnel. Qualquer outra coisa é vazamento.**

Todo o resto (DNS, IPv6, WebRTC, NTP, mDNS) é classificação mais fina dessa regra, ou verificação de coerência ao redor dela.

### 1.4 Objetivos

- Detectar vazamento de IP e de DNS em até **1 segundo**.
- Funcionar com qualquer túnel comum (WireGuard, OpenVPN, Tor, clientes comerciais) **sem configuração manual** na maioria dos casos.
- Não alterar o sistema de forma permanente: tudo o que a ferramenta muda é revertido no desarme ou com `opsecmon cleanup`.
- Não ser, ela mesma, uma fonte de vazamento.
- Produzir um registro verificável da sessão.

### 1.5 Não objetivos (v1)

- Não é um sistema operacional nem substitui Whonix/Qubes/Tails.
- Não é um cliente VPN nem um cliente Tor.
- Não protege contra o host comprometido com root (ver §22).
- Não testa fingerprint do navegador na v1 (exige extensão; ver §23).
- Não cobre Windows nem macOS na v1.

---

## 2. Modelo de ameaça

### 2.1 Adversário

Grupo criminoso com capacidade técnica alta, interesse em identificar e localizar o investigador, e disposição para violência física.

**Capacidades presumidas:**

- Opera sites, fóruns, painéis, servidores e canais que o operador visita, e vê IP de origem, resolvedor DNS, candidatos WebRTC, fingerprint do navegador e horários.
- Envia links e arquivos com beacons (canary tokens, documentos que "ligam para casa").
- Correlaciona identidades entre plataformas (usernames, horários, estilo).
- Pode comprar dados vazados ou de corretores (dados de provedores, geolocalização por IP).

**Capacidades não presumidas:** adversário em nível de Estado, controle do provedor do operador, correlação de tráfego global sobre o Tor.

### 2.2 O que a ferramenta cobre

| Ameaça | Cobertura v1 |
|---|---|
| Queda ou falha do túnel com tráfego saindo pela interface física | ✅ Detecta (≤1 s) e, no modo guarda estrito, impede |
| DNS resolvido fora do túnel | ✅ |
| IPv6 fora do túnel | ✅ |
| WebRTC/STUN fora do túnel | ✅ (pela regra central) |
| App ligado diretamente à interface física | ✅ com atribuição de processo (melhor esforço) |
| Troca de rede, novas interfaces, tethering USB | ✅ |
| Kill switch do cliente VPN alterado ou removido | ✅ |
| Incoerência da persona (IP de saída × timezone × idioma) | ✅ |
| Processos que revelam identidade (sync, mensageiros) | ✅ por lista de negação |
| Broadcasts na LAN com hostname (mDNS, LLMNR, NetBIOS) | ✅ |
| Fingerprint do navegador | ❌ v2 |
| Malware com root no host | ❌ fora do escopo |
| Correlação comportamental (horário, estilo, reuso de nomes) | ⚠️ checklist manual no preflight |

---

## 3. Princípios de design

1. **Fail-closed onde for possível; nunca fail-silent.** Se a ferramenta não consegue ver, o estado é **CINZA (visibilidade degradada)**, nunca verde. "Não sei" ≠ "seguro".
2. **Detecção passiva primeiro.** Checks ativos (consultar o IP de saída, por exemplo) são complementares, opcionais e passam apenas pelo túnel.
3. **Nenhum efeito colateral permanente.** Toda regra de firewall fica numa tabela própria do nftables; todo arquivo fica num diretório declarado. `opsecmon cleanup` remove tudo.
4. **Menor privilégio.** O daemon roda com um conjunto mínimo de capabilities; a GUI roda como o usuário comum.
5. **A ferramenta não fala com a internet** por conta própria: sem telemetria, sem verificação de updates, sem download de bases. Tudo o que ela precisa vem embutido.
6. **Tudo é registrado.** Cada check, alerta, ação, reconhecimento do operador e mudança de estado vira evento no log encadeado.
7. **Alertas que não passam despercebidos.** Alerta crítico ocupa a tela inteira e não se fecha com Esc.
8. **Testável.** Cada detector tem um cenário de autoteste que comprova que ele funciona naquela máquina, naquele momento.

---

## 4. Escopo da v1 e requisitos de sistema

### 4.1 Distribuições alvo

| Distribuição | Versões |
|---|---|
| Debian | 12, 13 |
| Ubuntu | 22.04, 24.04, 25.04+ |
| Fedora | 39+ |
| Kali Linux | rolling |

### 4.2 Requisitos

- Kernel ≥ 5.10 (6.x recomendado).
- nftables disponível no kernel (o binário `nft` **não** é necessário: a ferramenta fala netlink diretamente).
- systemd (para leitura do systemd-resolved e unidade opcional de serviço). Funcionar sem systemd é desejável, não obrigatório na v1.
- Execução como root (via `sudo`), com descarte imediato de privilégios para o conjunto do §18.3.
- Desktop opcional: GNOME, KDE, XFCE; X11 e Wayland (ver ressalvas em §15.4).

### 4.3 Túneis suportados na v1

| Tipo | Descoberta | Observações |
|---|---|---|
| WireGuard (kernel e wireguard-go) | Interface + `wgctrl` (peers, endpoints, último handshake, fwmark) | Inclui wg-quick e NetworkManager |
| OpenVPN | Interface `tun*`/`tap*` + sockets do processo `openvpn` | Management interface opcional |
| Tor (tor do sistema ou do Tor Browser) | Control port 9051/9151 (cookie) | Guards e bridges viram o allowlist |
| Clientes comerciais (Mullvad, Proton, IVPN etc.) | Interface + cgroup do serviço + sockets | Sem integração específica na v1, só detecção genérica |
| VPN → Tor, Tor sobre VPN | Combinação dos anteriores | O túnel "mais externo" define o allowlist da interface física |
| VMs no host (Whonix, VMs de análise) | Pela interface física do host | Tráfego em bridge ou NAT passa pela interface física e é visto |

### 4.4 Formas de distribuição

- **Modo portátil:** um único binário `opsecmon` (mais o binário opcional da GUI) rodando de uma pasta qualquer, com config e logs em diretório escolhido pelo operador (idealmente um volume cifrado).
- **Pacote:** `.deb` e `.rpm` com unidade systemd opcional `opsecmond.service`.

---

## 5. Arquitetura

### 5.1 Componentes

```
┌────────────────────────────────────────────────────────────────────┐
│                         opsecmond (root → caps mínimas)            │
│                                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────┐ │
│  │  Discovery   │  │   Sensores   │  │  Checks ativos│  │ Preflight│ │
│  │ (túnel, ifs, │  │ AF_PACKET    │  │ (IP de saída, │  │          │ │
│  │  endpoints)  │  │ netlink      │  │  pelo túnel)  │  │          │ │
│  └──────┬───────┘  │ nflog        │  └──────┬───────┘  └────┬────┘ │
│         │          │ /proc, D-Bus │         │               │      │
│         │          │ inotify      │         │               │      │
│         │          └──────┬───────┘         │               │      │
│         ▼                 ▼                 ▼               ▼      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │           Motor de checks (plugins) → eventos               │   │
│  └───────────────────────────┬─────────────────────────────────┘   │
│                              ▼                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Motor de severidade e estado  →  Motor de respostas        │   │
│  │  (dedup, agregação, estado global)  (alerta, bloqueio, kill)│   │
│  └───────────┬──────────────────────────────┬──────────────────┘   │
│              ▼                              ▼                      │
│  ┌──────────────────────┐        ┌───────────────────────┐         │
│  │ Log encadeado (age)  │        │ Guarda (nftables)     │         │
│  └──────────────────────┘        └───────────────────────┘         │
│              ▲                                                     │
│              │  Servidor IPC (Unix socket, SO_PEERCRED)            │
└──────────────┼─────────────────────────────────────────────────────┘
               │
     ┌─────────┴──────────┬───────────────────┐
     ▼                    ▼                   ▼
 opsecmon (CLI)     opsecmon-gui (usuário)  opsecmon tui
```

| Componente | Responsabilidade | Privilégio |
|---|---|---|
| `opsecmond` | Descoberta, sensores, checks, estado, respostas, log, guarda | root → capabilities mínimas |
| `opsecmon` (CLI) | Comandos do operador; também inicia o daemon em primeiro plano no modo portátil | usuário (sobe para root só para iniciar o daemon) |
| `opsecmon-gui` | Bandeja, painel, alerta em tela cheia | usuário comum |
| `opsecmon tui` | Painel em terminal | usuário comum |

### 5.2 Modos de execução

| Modo | Como | Uso |
|---|---|---|
| Portátil (padrão) | `sudo ./opsecmon run -p op.yaml` sobe o daemon em primeiro plano e abre a GUI como o usuário que chamou o sudo (`SUDO_UID`) | Instalação na hora |
| Serviço | `opsecmond.service` + `opsecmon arm/disarm` | Máquinas dedicadas |

### 5.3 Modelo de plugins de check

Cada check implementa a mesma interface (Go):

```go
type Check interface {
    ID() string                  // "NET-001"
    Kind() Kind                  // Passive | Active | Preflight
    DefaultSeverity() Severity
    Start(ctx context.Context, env *Env, out chan<- Event) error
    Reconfigure(env *Env) error  // chamado quando a descoberta muda (endpoint novo etc.)
    SelfTest(ctx context.Context) []SelfTestCase
}
```

Os checks são compilados no binário (sem carregamento dinâmico de código, por segurança). A severidade e as ações de cada check podem ser sobrescritas pelo perfil.

---

## 6. Ciclo de vida de uma operação

### 6.1 Máquina de estados da sessão

```
          baseline create                  preflight OK
 [SEM BASELINE] ──────────▶ [PRONTO] ─────────────────▶ [VERIFICADO]
                               ▲                              │ arm
                               │ disarm                       ▼
                               │                         ┌─────────┐
                               └──────────────────────── │ ARMADO  │◀─┐
                                                         └────┬────┘  │ unpanic
                                                              │ evento│ (após re-check)
                                                              ▼ crítico
                                                         ┌─────────┐  │
                                                         │ PÂNICO  │──┘
                                                         └─────────┘
```

Dentro de **ARMADO**, o estado global é a cor:

| Cor | Significado |
|---|---|
| 🟢 VERDE | Todos os checks passam |
| 🟡 AMARELO | Há aviso aberto (WARNING) |
| 🔴 VERMELHO | Há alerta crítico aberto (CRITICAL) |
| ⚪ CINZA | Visibilidade degradada: algum sensor caiu, perdeu pacotes ou o túnel não foi identificado |

Regra de precedência: VERMELHO > CINZA > AMARELO > VERDE.

### 6.2 Fases

1. **Baseline** (antes da operação, em rede segura): captura a identidade real (§11).
2. **Preflight**: checklist de configuração (§8.7). Itens com falha crítica bloqueiam o `arm`, a menos que o operador use `--force` com justificativa, que fica registrada no log.
3. **Arm**: inicia sensores, aplica o guarda (se habilitado), gera a chave de sessão e abre o log.
4. **Execução**: monitoramento contínuo, alertas e respostas.
5. **Pânico** (automático ou manual): bloqueio total, encerramento de processos configurados, alerta em tela cheia.
6. **Unpanic**: exige reconhecimento explícito do operador e uma nova rodada de checks antes de liberar a rede.
7. **Disarm**: remove o guarda, fecha e assina o log, gera o relatório.
8. **Cleanup** (opcional): remove qualquer resto (tabelas nftables, sockets, arquivos temporários).

---

## 7. Descoberta automática do ambiente

Rodada no `arm` e repetida sempre que o netlink sinalizar mudança de link, endereço ou rota.

### 7.1 O que é descoberto

| Item | Fonte |
|---|---|
| Interfaces físicas | netlink (`RTM_NEWLINK`), `/sys/class/net/*/device` (tem dispositivo de hardware), tipo (Ethernet/Wi-Fi/USB) |
| Interfaces de túnel | Tipo de link (`wireguard`, `tun`, `tap`), nomes conhecidos (`wg*`, `tun*`, `proton*`, `mullvad*`, `nordlynx` etc.) |
| Endpoints do túnel | WireGuard: `wgctrl` (peers → endpoint IP:porta). OpenVPN: sockets do processo. Tor: `GETINFO entry-guards` e primeiro salto dos circuitos via control port |
| Marca e cgroup do túnel | fwmark do WireGuard; cgroup v2 do serviço VPN (`/proc/<pid>/cgroup`) |
| Rota default e policy routing | netlink (`ip route`, `ip rule`, tabelas) |
| DNS efetivo | `/etc/resolv.conf`, systemd-resolved via D-Bus (DNS por link, `DefaultRoute`), NetworkManager via D-Bus |
| Estado do IPv6 | Endereços globais por interface, rotas default v6, `sysctl net.ipv6.conf.*.disable_ipv6` |
| Rede Wi-Fi atual | NetworkManager D-Bus (SSID, BSSID) ou nl80211 |

### 7.2 Modo aprendizado

Se o endpoint do túnel não puder ser determinado (cliente proprietário, configuração exótica):

1. O estado fica **CINZA**.
2. A GUI ou CLI mostra, por 10 s, os destinos observados saindo pela interface física, agrupados por processo/cgroup.
3. O operador confirma qual é o endpoint, e a escolha é registrada no log.
4. Alternativa: declarar os endpoints no perfil (`egress.endpoints`).

### 7.3 Atualização dinâmica

Quando o cliente VPN troca de servidor, ou o Tor troca de guard, o daemon atualiza o conjunto de endpoints permitidos (em memória e no set do nftables) em até **1 s**, gerando evento `INFO discovery.endpoint_changed`.

---

## 8. Catálogo de checks

Convenções: **P** = passivo, **A** = ativo, **PF** = preflight (pontual). Severidade padrão: **C** = CRITICAL, **W** = WARNING, **I** = INFO.

### 8.1 Rede (NET)

| ID | Nome | Tipo | Método | Sev. |
|---|---|---|---|---|
| NET-001 | **Tráfego fora do túnel** | P | Socket AF_PACKET em cada interface física, recebendo só pacotes de saída (`PACKET_OUTGOING`), com filtro BPF *no kernel* que descarta o tráfego permitido (endpoints do túnel, DHCP, ARP e, se habilitado, LAN). Todo pacote que chega ao espaço de usuário é um vazamento. | C |
| NET-002 | Vazamento bloqueado (tentativa) | P | No modo guarda, a regra de drop faz `log group` (NFLOG); o daemon lê via netlink e registra tentativa, UID e destino. | W |
| NET-003 | IPv6 fora do túnel | P | Endereço global ou rota default v6 numa interface física quando `expect.ipv6: false` ou quando o túnel não carrega v6. | C |
| NET-004 | Rota default fora do túnel | P | Eventos netlink de rota/regra; avalia se a rota efetiva para um destino de teste (RFC 5737) sai pelo túnel. | C |
| NET-005 | Mudança de rota ou policy routing | P | Eventos netlink `RTM_NEWROUTE`/`RTM_DELROUTE`/`RTM_NEWRULE`. | W |
| NET-006 | Interface nova ou link up | P | `RTM_NEWLINK` (tethering USB, adaptador novo, Wi-Fi associando). | W |
| NET-007 | Mudança de rede Wi-Fi | P | SSID/BSSID mudou durante a sessão. Se o SSID bate com a baseline, sobe para C. | W/C |
| NET-008 | MAC real em uso | P/PF | Compara o MAC atual com o permanente (`IFLA_PERM_ADDRESS`) em interfaces físicas ativas. | W |
| NET-009 | Broadcast na LAN com identificadores | P | Saída para mDNS 5353, LLMNR 5355, NetBIOS 137/138, SSDP 1900, inspecionando o hostname anunciado. | W |
| NET-010 | Socket ligado à interface física | P | Varredura de `/proc/net/{tcp,tcp6,udp,udp6}` a cada 1 s, com mapa inode→PID; conexão com IP local da interface física para destino fora do allowlist. Serve para **atribuir processo** a eventos do NET-001. | C |
| NET-011 | IP de saída (verificação ativa) | A | Pelo túnel, em intervalo aleatório (padrão 3–10 min), em 2+ endpoints configurados; ASN e país resolvidos **offline** pela base embutida. ASN da baseline = C; país diferente do perfil = W. | C/W |
| NET-012 | Classificação de STUN/WebRTC | P | Subclassificação do NET-001 quando a porta de destino é STUN (3478, 5349, 19302–19309), para deixar o alerta mais claro. | C |

### 8.2 DNS (DNS)

| ID | Nome | Tipo | Método | Sev. |
|---|---|---|---|---|
| DNS-001 | DNS fora do túnel | P | Subclassificação do NET-001 para 53/udp, 53/tcp e 853/tcp. Decodifica o nome consultado e o registra (cifrado). | C |
| DNS-002 | Resolvedor do provedor configurado | P | Resolvedores efetivos (resolv.conf, resolved, NM) comparados com a baseline. | C |
| DNS-003 | Resolvedor em link físico com DefaultRoute | P | systemd-resolved com DNS por link na interface física e `DefaultRoute=yes`: as consultas podem sair por fora conforme a prioridade. | W |
| DNS-004 | Configuração de DNS alterada | P | inotify em `/etc/resolv.conf` e sinais D-Bus do resolved/NM. | W |
| DNS-005 | Canário de DNS (opcional) | A | Consulta `<aleatório>.<zona-canário>`; o servidor autoritativo controlado pela instituição informa qual resolvedor perguntou. **Desabilitado na v1 por padrão**; exige o componente de servidor (§23). | C |

### 8.3 Túnel (TUN)

| ID | Nome | Tipo | Método | Sev. |
|---|---|---|---|---|
| TUN-001 | Túnel ausente ou down | P | Interface de túnel esperada sumiu ou ficou `DOWN`. | C |
| TUN-002 | Handshake WireGuard antigo | P | `wgctrl`: último handshake > 180 s com tráfego pendente. | W |
| TUN-003 | Tor sem bootstrap ou sem circuito | P | Control port: `status/bootstrap-phase` < 100, ou `status/circuit-established=0`. | C |
| TUN-004 | Kill switch alterado | P | Snapshot do ruleset nftables completo no `arm` (hash por tabela); reamostragem a cada 5 s e eventos `NFT_MSG_*`. Mudança = W; sumiço da tabela do cliente VPN = C. | W/C |
| TUN-005 | Split tunneling ativo | P/PF | Policy routing com exclusões, cgroups excluídos do túnel (detecção genérica) e processos lançados com `mullvad-exclude` ou equivalente. | W |
| TUN-006 | Endpoint inesperado | P | O túnel passou a falar com um endpoint fora do país ou provedor declarado no perfil. | W |

### 8.4 Host (HOST)

| ID | Nome | Tipo | Método | Sev. |
|---|---|---|---|---|
| HOST-001 | Processo da lista de negação | P | Varredura de `/proc` a cada 2 s, com casamento por `comm`, caminho do executável e cgroup. Severidade definida pelo perfil. | W/C |
| HOST-002 | Câmera ou microfone em uso | P | `/dev/video*` aberto por algum processo (via `/proc/*/fd`); streams de captura no PipeWire/PulseAudio. | W |
| HOST-003 | Compartilhamento de tela ou acesso remoto | P | Processos conhecidos (AnyDesk, TeamViewer, sessões de screencast no portal xdg). | W |
| HOST-004 | Hostname real | PF/P | Hostname atual = hostname da baseline. | W |
| HOST-005 | Timezone e locale fora do perfil | PF/P | `/etc/localtime`, `timedatectl` via D-Bus, `LANG`/`LC_*` da sessão do usuário. | W |
| HOST-006 | Disco e swap sem cifra | PF | `lsblk`/sysfs: raiz sobre dm-crypt; swap sobre dm-crypt ou zram. | W |
| HOST-007 | Sincronização de horário fora do túnel | PF | Configuração do timesyncd/chrony/ntpd (o tráfego em si é coberto pelo NET-001). | I |
| HOST-008 | Redes Wi-Fi salvas com autoconnect | PF | Conexões salvas no NetworkManager com SSIDs da baseline e autoconnect ativo: a máquina pode se associar à rede de casa sozinha. | W |

### 8.5 Persona (PER)

| ID | Nome | Tipo | Método | Sev. |
|---|---|---|---|---|
| PER-001 | Coerência geográfica | P | País do IP de saída (NET-011, offline) × timezone do sistema × locale × layout de teclado × `expect` do perfil. | W |
| PER-002 | Configuração de navegador | PF | Lê `prefs.js`/`user.js` dos perfis Firefox e Tor Browser (`media.peerconnection.enabled`, `network.trr.mode`, `network.proxy.socks_remote_dns`) e as policies do Chromium (`WebRtcIPHandling`). | W |
| PER-003 | Perfil pessoal do navegador | PF/P | Navegador aberto com o perfil padrão do usuário, e não com um perfil declarado para a persona. | W |

### 8.6 Autodiagnóstico (SELF)

| ID | Nome | Tipo | Método | Sev. |
|---|---|---|---|---|
| SELF-001 | Sensor parado | P | Cada sensor emite heartbeat; ausência por > 3 s → estado CINZA. | C (cinza) |
| SELF-002 | Perda de pacotes na captura | P | Estatísticas do ring AF_PACKET (`PACKET_STATISTICS`, `tp_drops`) > 0. | W (cinza) |
| SELF-003 | GUI desconectada | P | A GUI parou de responder ao heartbeat; o daemon cai para notificação via `notify-send` e som. | W |
| SELF-004 | Selftest desatualizado | PF | Último selftest há mais de 24 h, ou nunca rodado nesta máquina. | W |
| SELF-005 | Relógio alterado | P | Salto de relógio (diferença entre o tempo monotônico e o de parede) > 2 s. | I |

### 8.7 Checklist do preflight

O preflight executa todos os checks **PF**, uma passada única dos **P**, e um checklist humano que o operador confirma item a item. As confirmações vão para o log.

**Automático:** NET-003, NET-004, NET-008, DNS-002, DNS-003, TUN-001, TUN-003, TUN-005, HOST-001, HOST-004…008, PER-001…003, SELF-004.

**Manual (confirmação):**

- [ ] Nenhuma conta pessoal logada no navegador ou nos apps desta sessão
- [ ] O username da persona não é reutilizado de nenhuma outra identidade
- [ ] O celular pessoal não está na mesma rede, ou está em modo avião
- [ ] Os arquivos recebidos de alvos serão abertos apenas em VM offline
- [ ] O horário da operação não segue o padrão do expediente pessoal

---

## 9. Severidade, estados e respostas

### 9.1 Níveis

| Nível | Semântica | Efeito no estado |
|---|---|---|
| INFO | Fato relevante, sem risco | Nenhum |
| WARNING | Configuração arriscada ou evento que pode virar vazamento | AMARELO |
| CRITICAL | Vazamento ocorrido ou iminente | VERMELHO + respostas |

### 9.2 Ciclo de vida do alerta

`aberto → reconhecido → resolvido`

- Um **CRITICAL** só pode ser reconhecido por ação explícita (botão + confirmação digitada na GUI, ou `opsecmon ack <id> --reason "..."`). O motivo vai para o log.
- Um alerta é **resolvido** automaticamente quando a condição deixa de existir por ≥ 10 s, ou manualmente.
- **Deduplicação:** eventos iguais (mesmo check, destino e processo) dentro de 5 s são agregados num único alerta com contador.

### 9.3 Ações de resposta

| Ação | Efeito | Latência alvo |
|---|---|---|
| `alert_tray` | Ícone muda de cor + notificação | ≤ 200 ms |
| `alert_sound` | Som distinto por severidade | ≤ 200 ms |
| `alert_fullscreen` | Janela em tela cheia, sempre no topo, que não fecha com Esc | ≤ 500 ms |
| `block_all` | Aplica a tabela `opsecmon_panic` (§10.4) | ≤ 200 ms |
| `kill_processes` | SIGKILL nos processos listados no perfil (navegadores, por exemplo) | ≤ 200 ms |
| `kill_offender` | SIGKILL no processo atribuído ao evento (se a atribuição tiver confiança alta) | ≤ 200 ms |
| `link_down` | `ip link set <física> down` em todas as interfaces físicas | ≤ 200 ms |
| `lock_screen` | Bloqueia a sessão gráfica (loginctl) | ≤ 500 ms |

As ações são executadas **pelo daemon**, nunca pela GUI, para que funcionem mesmo se a GUI travar. Toda ação gera evento `response.executed` com resultado (sucesso ou erro).

### 9.4 Respostas padrão

| Severidade | Modo observador | Modo guarda |
|---|---|---|
| WARNING | `alert_tray`, `alert_sound` | `alert_tray`, `alert_sound` |
| CRITICAL | `alert_fullscreen`, `alert_sound` | `block_all`, `kill_processes`, `alert_fullscreen`, `alert_sound` |

Configuráveis por check no perfil (§12).

### 9.5 Pânico e unpanic

- **Pânico** = estado em que `block_all` está ativo. Entra automaticamente (CRITICAL em modo guarda) ou por `opsecmon panic` / botão na GUI / atalho global (opcional).
- **Unpanic** exige:
  1. reconhecimento de todos os CRITICAL abertos;
  2. uma nova rodada de checks de estado (NET-003, NET-004, DNS-002, TUN-001/003) passando;
  3. confirmação explícita do operador.
- Com `panic.keep_tunnel: true`, o pânico mantém apenas o túnel (equivale ao guarda estrito); o padrão é **bloquear tudo**, inclusive o túnel.

---

## 10. Modo guarda (nftables)

### 10.1 Submodos

| Submodo | Comportamento | Quando usar |
|---|---|---|
| `off` (observador) | Nenhuma regra é aplicada; só detecta e alerta | Ambientes onde não se pode mexer no firewall |
| `reactive` | Sem regras permanentes; aplica `block_all` ao detectar CRITICAL. **O primeiro pacote vazado já saiu.** | Quando o allowlist não é confiável |
| `strict` (**recomendado**) | Aplica no `arm` uma tabela que só permite túnel + endpoints + DHCP + loopback. Vazamentos são **impedidos** e viram NET-002 (tentativa bloqueada). Se o daemon morrer, a tabela permanece: **fail-closed**. | Padrão quando o guarda está habilitado |

### 10.2 Propriedade do nftables usada no design

No nftables, um `drop` em **qualquer** chain base é definitivo: um `accept` em outra tabela (por exemplo, a do cliente VPN) não o anula. Por isso, a tabela do `opsecmon` só **acrescenta restrições** e não depende da ordem nem do conteúdo das regras de terceiros. Ela nunca altera as tabelas existentes.

### 10.3 Tabela do modo estrito (referência)

```nft
table inet opsecmon {
    set tunnel_ifaces   { type ifname; }                  # ex.: "wg0"
    set endpoints4      { type ipv4_addr . inet_service; flags timeout; }
    set endpoints6      { type ipv6_addr . inet_service; flags timeout; }
    set phys_ifaces     { type ifname; }

    chain output {
        type filter hook output priority filter - 10; policy accept;
        oifname "lo" accept
        oifname @tunnel_ifaces accept
        oifname != @phys_ifaces accept                    # outras interfaces virtuais
        meta mark 0x0000ca6c accept                       # encapsulamento WireGuard (fwmark descoberto)
        ip  daddr . udp dport @endpoints4 accept
        ip  daddr . tcp dport @endpoints4 accept
        ip6 daddr . udp dport @endpoints6 accept
        ip6 daddr . tcp dport @endpoints6 accept
        udp sport 68 udp dport 67 accept                  # DHCPv4
        meta l4proto ipv6-icmp icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
        log group 4242 prefix "OPSECMON-BLOCK " drop      # → NET-002
    }

    chain forward {
        type filter hook forward priority filter - 10; policy accept;
        oifname @phys_ifaces log group 4242 prefix "OPSECMON-FWD " drop   # VMs em NAT saindo por fora
    }
}
```

Notas:
- Os sets são atualizados pelo daemon via netlink conforme a descoberta (§7.3). Os endpoints recebem `timeout` para expirar sozinhos quando deixam de ser usados.
- O fwmark e o cgroup do cliente VPN entram como regras extras, gerados a partir da descoberta (por exemplo, `socket cgroupv2 level 2 "system.slice/<cliente-vpn>.service" accept`).
- Tráfego de LAN só é liberado se `network.allow_lan: true` no perfil.
- VMs em **bridge** têm o tráfego filtrado pela hook `forward` da família `bridge` (tabela `bridge opsecmon`, gerada só quando há bridges com interfaces físicas).

### 10.4 Tabela de pânico

```nft
table inet opsecmon_panic {
    chain output  { type filter hook output  priority filter - 20; policy drop; oifname "lo" accept; }
    chain forward { type filter hook forward priority filter - 20; policy drop; }
    chain input   { type filter hook input   priority filter - 20; policy drop; iifname "lo" accept; }
}
```

Aplicada atomicamente (uma única transação netlink). Conexões já estabelecidas também são cortadas, porque a política é aplicada pacote a pacote.

### 10.5 Remoção

- O `disarm` remove `opsecmon`, `opsecmon_panic` e `bridge opsecmon` numa transação.
- `opsecmon cleanup` remove essas tabelas mesmo sem daemon rodando (por exemplo, depois de um crash ou reboot no meio da sessão).
- As tabelas **não** são persistidas: um reboot as apaga. Isso é intencional e documentado: depois de um reboot, o operador precisa rodar `arm` de novo antes de voltar a operar.

---

## 11. Linha de base (baseline)

### 11.1 O que contém

| Campo | Origem | Armazenamento |
|---|---|---|
| IP público real (v4 e v6) | 2+ consultas sem túnel, só no `baseline create` | hash salgado (SHA-256 + salt) e prefixo /24 (v4) ou /48 (v6) |
| ASN e provedor | Base offline embutida | texto (no arquivo cifrado) |
| Resolvedores DNS do provedor | Configuração no momento da baseline | hash salgado + texto |
| Gateway padrão (IP, MAC) | netlink, vizinhos | hash salgado |
| SSIDs conhecidos | Conexões salvas no NetworkManager + SSID atual | hash salgado |
| MACs permanentes | `IFLA_PERM_ADDRESS` | hash salgado |
| Hostname, nome de usuário | sistema | hash salgado |
| Timezone e locale reais | sistema | texto |

Os hashes salgados permitem comparar valores exatos sem guardar o valor em claro. O prefixo e o ASN permitem casamento aproximado, por exemplo quando o provedor troca o IP dentro do mesmo bloco.

### 11.2 Criação

- `opsecmon baseline create`: precisa ser rodado **sem túnel**, numa rede considerada segura (a de casa, por exemplo). Avisa e pede confirmação se detectar túnel ativo.
- `opsecmon baseline create --manual`: não faz nenhuma consulta de rede; o operador informa ASN, provedor, SSIDs e resolvedores.
- O resultado é um arquivo único `baseline.age`, cifrado com **age** (passphrase com scrypt, ou destinatário X25519 da instituição).

### 11.3 Uso

O daemon decifra a baseline na memória no `arm` (pede a passphrase) e não a grava em disco em claro em nenhum momento.

---

## 12. Perfil de operação

### 12.1 Formato

YAML, validado contra um JSON Schema embutido (`opsecmon profile validate`).

### 12.2 Exemplo completo

```yaml
version: 1
operation:
  id: "OP-2026-117"            # identificador interno
  persona: "falcao"
  operator: "agente-07"        # pseudônimo; opcional

egress:
  type: wireguard              # wireguard | openvpn | tor | vpn+tor | auto
  expect_country: NL
  expect_asn: []               # opcional: ASNs aceitos para o IP de saída
  endpoints: []                # opcional: "203.0.113.10:51820" (se a descoberta não resolver)
  tor_control: auto            # auto | "127.0.0.1:9151"

expect:
  timezone: UTC
  locale: en_US.UTF-8
  keyboard: us
  ipv6: false

network:
  allow_lan: false
  allow_dhcp: true

baseline:
  file: /media/op/vault/baseline.age

guard:
  mode: strict                 # off | reactive | strict
  panic:
    keep_tunnel: false

active_checks:
  enabled: true
  egress_ip:
    interval: [180s, 600s]     # intervalo aleatório
    endpoints:
      - https://check.torproject.org/api/ip
      - https://am.i.mullvad.net/json
  dns_canary:
    enabled: false
    zone: ""

processes:
  deny:
    - { match: comm, value: onedrive,         severity: CRITICAL }
    - { match: comm, value: dropbox,          severity: CRITICAL }
    - { match: comm, value: telegram-desktop, severity: WARNING }
    - { match: comm, value: discord,          severity: WARNING }
  kill_on_panic: [firefox, tor-browser, chromium, chrome]

browsers:
  persona_profiles:
    - ~/.mozilla/firefox/xxxx.falcao

overrides:                     # sobrescreve severidade ou ações por check
  NET-009: { severity: WARNING, actions: [alert_tray] }
  HOST-002: { severity: CRITICAL }

storage:
  dir: /media/op/vault/opsecmon      # logs, relatórios, estado
  log_recipient: "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq"   # chave pública age da instituição (exemplo)

ui:
  language: pt-BR
  fullscreen_alerts: true
  sound: true
```

### 12.3 Defaults

Na falta de perfil, `opsecmon run` usa: `egress.type: auto`, `guard.mode: off`, checks ativos desabilitados e todos os passivos habilitados. Isso é útil para uma primeira inspeção rápida, mas **o modo recomendado para operação é sempre com perfil**.

---

## 13. Logs, relatório e cadeia de custódia

### 13.1 Formato do evento

JSON Lines, um evento por linha:

```json
{
  "seq": 1042,
  "ts": "2026-11-15T14:03:22.418213Z",
  "mono_ns": 81234567890123,
  "session": "5f0c9e2a-7b1d-4c3e-9a8f-2d6b1e0c4a77",
  "type": "check.alert",
  "check": "DNS-001",
  "severity": "CRITICAL",
  "data": {
    "iface": "wlp2s0",
    "proto": "udp",
    "dst": "198.51.100.53",
    "dport": 53,
    "qname_enc": "age:…",
    "proc": { "pid": 4121, "comm": "firefox", "uid": 1000, "confidence": "high" }
  },
  "actions": ["block_all", "kill_processes", "alert_fullscreen"],
  "prev": "sha256:9b1f…",
  "hash": "sha256:4c7a…"
}
```

### 13.2 Integridade

- **Encadeamento:** `hash = SHA-256(prev || JSON canônico do evento sem o campo hash)`.
- **Assinatura:** no `arm` é gerado um par Ed25519 de sessão. A chave pública vai no primeiro evento (`session.start`); no `disarm`, o hash final é assinado (`session.end`). A chave privada existe só na memória e é descartada no fim.
- Opcionalmente, a chave pública da sessão é assinada por uma chave da instituição (§24).
- `opsecmon verify <sessão>` valida a cadeia completa e a assinatura.

### 13.3 Armazenamento

- Os segmentos de log são rotacionados a cada 5 min ou 10 000 eventos, cada um num arquivo `age` separado (`events-0001.jsonl.age`…). Um crash perde no máximo o segmento corrente, e os demais continuam decifráveis.
- Dados sensíveis dentro do evento (nomes DNS consultados, títulos de janela) têm uma segunda camada de cifra por campo.
- Tudo fica em `storage.dir`; nada vai para `/var/log` nem para o journald, exceto uma linha mínima de início e fim, configurável para nenhuma.

### 13.4 Timestamps

UTC com precisão de microssegundos, mais o relógio monotônico. Saltos de relógio são registrados (SELF-005). O relógio de parede **não** é considerado confiável para provar ordem; a ordem é dada por `seq` e pela cadeia de hashes.

### 13.5 Relatório

`opsecmon report <sessão> --format md|json` gera:

- Identificação: operação, persona, pseudônimo do operador, hash do perfil e hash da baseline (nunca o conteúdo).
- Duração, estado em cada intervalo (linha do tempo por cor) e percentual do tempo em VERDE.
- Todos os alertas, com reconhecimento e motivo.
- Ações de resposta executadas.
- Resultado do preflight e do último selftest.
- Hash final, assinatura e chave pública da sessão.

---

## 14. CLI

### 14.1 Comandos

| Comando | Descrição |
|---|---|
| `opsecmon baseline create [--manual] [--out FILE]` | Cria a baseline cifrada |
| `opsecmon baseline show [FILE]` | Mostra o conteúdo (pede a passphrase; os hashes aparecem truncados) |
| `opsecmon profile init [--out FILE]` | Gera um perfil comentado |
| `opsecmon profile validate FILE` | Valida contra o schema |
| `opsecmon discover` | Mostra o que foi descoberto do ambiente (sem armar) |
| `opsecmon preflight -p FILE` | Roda o preflight e o checklist |
| `opsecmon run -p FILE [--guard off\|reactive\|strict] [--no-gui] [--tui] [--no-active]` | Modo portátil: sobe o daemon em primeiro plano e arma |
| `opsecmon arm -p FILE` / `opsecmon disarm` | Quando o daemon roda como serviço |
| `opsecmon status [--json]` | Estado atual, alertas abertos, sensores |
| `opsecmon events [--follow] [--severity S]` | Fluxo de eventos |
| `opsecmon ack ID --reason TEXT` | Reconhece um alerta |
| `opsecmon panic` / `opsecmon unpanic` | Bloqueio manual / liberação |
| `opsecmon selftest [--case ID]` | Roda o autoteste (§17) |
| `opsecmon report SESSÃO [--format md\|json]` | Gera o relatório |
| `opsecmon verify SESSÃO` | Verifica a integridade da sessão |
| `opsecmon cleanup` | Remove tabelas nftables, socket e arquivos temporários |
| `opsecmon version` | Versão, commit e hash do binário |

### 14.2 Códigos de saída

| Código | Significado |
|---|---|
| 0 | Sucesso |
| 1 | Erro genérico |
| 2 | Preflight com falha crítica |
| 3 | A sessão terminou com pelo menos um CRITICAL |
| 4 | A verificação de integridade falhou |
| 10 | Privilégios insuficientes |
| 11 | Requisito de sistema ausente (kernel, nftables) |

---

## 15. GUI e TUI

### 15.1 Bandeja

- Ícone com a cor do estado global (VERDE, AMARELO, VERMELHO, CINZA) e contador de alertas abertos.
- Menu: abrir painel, pânico, selftest, desarmar.

### 15.2 Painel principal

- **Cabeçalho:** operação e persona, tempo de sessão, modo do guarda, IP e país de saída (último check ativo), túnel identificado.
- **Grade de checks:** um cartão por categoria (Rede, DNS, Túnel, Host, Persona, Autodiagnóstico); cada check com estado, última avaliação e detalhe.
- **Linha do tempo:** eventos em ordem, filtráveis por severidade e por check.
- **Botões:** Pânico (sempre visível, vermelho), Selftest, Reconhecer, Desarmar.

### 15.3 Alerta em tela cheia

- Fundo vermelho, título do check, explicação em uma frase do que significa, destino e processo envolvidos e ações já executadas ("Rede bloqueada. Navegadores encerrados.").
- Não fecha com Esc nem com clique fora. Só fecha com "Reconhecer" + motivo digitado.
- Som repetido a cada 10 s até o reconhecimento (configurável).

### 15.4 Ressalvas de Wayland

No Wayland, "sempre no topo" e janelas em tela cheia que tomam o foco não são garantidos em todos os compositores (GNOME em especial). Mitigação: o daemon **sempre** envia também uma notificação com urgência crítica (`org.freedesktop.Notifications`, urgency=2) e toca o som; a GUI tenta fullscreen e registra se conseguiu.

### 15.5 TUI

Painel em terminal com as mesmas informações (estado, grade de checks e eventos) e atalhos para `p` (pânico), `a` (reconhecer), `s` (selftest) e `q` (sair sem desarmar).

### 15.6 Idioma

pt-BR por padrão; en-US disponível. Todos os textos de alerta têm versão curta (título) e longa (o que fazer).

---

## 16. IPC entre daemon e interfaces

- **Transporte:** Unix domain socket em `/run/opsecmon/opsecmon.sock` (modo portátil: `$XDG_RUNTIME_DIR` do usuário que chamou o sudo), permissão `0600` com dono = usuário operador.
- **Autenticação:** `SO_PEERCRED`; só o UID do operador e o root são aceitos. Não há nenhuma porta TCP.
- **Protocolo:** JSON-RPC 2.0, uma mensagem por linha.

| Método | Descrição |
|---|---|
| `status.get` | Estado global, sensores, alertas abertos |
| `events.subscribe` | Fluxo de eventos (push) |
| `events.query` | Consulta histórica da sessão |
| `alert.ack` | Reconhecimento com motivo |
| `session.arm` / `session.disarm` | Controle da sessão |
| `panic.engage` / `panic.release` | Pânico |
| `selftest.run` | Dispara o autoteste |
| `discovery.get` / `discovery.confirm_endpoint` | Descoberta e modo aprendizado |
| `heartbeat` | Bidirecional, a cada 1 s |

---

## 17. Autoteste (selftest)

### 17.1 Princípio

O autoteste **não pode gerar um vazamento real**. Por isso todo tráfego de teste usa destinos não roteáveis na internet:

- IPv4: blocos de documentação RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
- IPv6: `2001:db8::/32` (RFC 3849)

Esses pacotes saem pela interface física e são descartados pela rede, sem chegar a nenhum serviço. O provedor do operador, no máximo, vê um pacote para um endereço de documentação. Os eventos gerados no autoteste são marcados `selftest: true` e não disparam respostas reais: o motor de respostas executa em **dry-run**, exceto no caso `RESP-001`.

### 17.2 Casos

| Caso | Valida | Como |
|---|---|---|
| ST-NET-001 | NET-001 | UDP para `192.0.2.1:9` com `SO_BINDTODEVICE` na interface física |
| ST-NET-002 | NET-002 (modo estrito) | Mesmo teste; deve aparecer como tentativa bloqueada |
| ST-NET-003 | NET-003 | UDP para `[2001:db8::1]:9` pela interface física (se houver v6) |
| ST-NET-006 | NET-006 | Cria e remove uma interface `dummy` temporária |
| ST-NET-010 | NET-010 | TCP SYN para `198.51.100.1:443` pela interface física; precisa atribuir ao processo do selftest |
| ST-NET-012 | NET-012 | UDP para `203.0.113.1:3478` |
| ST-DNS-001 | DNS-001 | Consulta DNS para `192.0.2.53:53` pela interface física, com nome aleatório |
| ST-DNS-004 | DNS-004 | Altera e restaura um arquivo de teste observado (não o resolv.conf real) |
| ST-TUN-004 | TUN-004 | Cria e remove uma tabela nftables temporária `opsecmon_selftest` |
| ST-HOST-001 | HOST-001 | Inicia um processo fictício com nome da lista de negação do teste |
| ST-SELF-001 | SELF-001 | Pausa um sensor por 4 s; o estado deve ir para CINZA e voltar |
| RESP-001 | `block_all` | Aplica e remove `opsecmon_panic` de verdade, mede a latência e confirma que o tráfego de teste foi bloqueado. Pede confirmação, porque derruba a conexão por ~1 s. |

### 17.3 Resultado

Tabela de pass/fail com a latência de detecção de cada caso, registrada no log e no estado local (usado pelo SELF-004). Qualquer falha deixa o preflight em WARNING, e uma falha no ST-NET-001 o deixa em CRITICAL.

---

## 18. Segurança da própria ferramenta

### 18.1 Sem comunicação própria

- Nenhuma telemetria, verificação de update, download de base ou relatório de crash.
- As únicas conexões de rede são os checks ativos explicitamente habilitados, sempre pelo túnel.
- **Teste automatizado no CI:** o daemon roda num network namespace isolado durante a suíte completa, e o teste falha se houver qualquer conexão não esperada.

### 18.2 Build e distribuição

- Builds reprodutíveis (Go com `-trimpath`, versões fixadas, `CGO_ENABLED` documentado).
- Binários e pacotes assinados (minisign ou Sigstore, conforme a política da instituição); `opsecmon version` mostra o hash do próprio binário.
- SBOM (CycloneDX) publicado junto de cada release.
- Distribuição por repositório interno da instituição, nunca por download público na hora da operação.

### 18.3 Privilégios

Depois de inicializar como root, o daemon mantém só:

| Capability | Uso |
|---|---|
| `CAP_NET_RAW` | Sockets AF_PACKET |
| `CAP_NET_ADMIN` | nftables, netlink, link down, NFLOG |
| `CAP_KILL` | Encerrar processos (respostas) |
| `CAP_SYS_PTRACE` | Ler `/proc/<pid>/fd` de outros usuários (atribuição de sockets) |
| `CAP_DAC_READ_SEARCH` | Ler configurações e perfis de navegador |

Além disso: `PR_SET_NO_NEW_PRIVS`, filtro seccomp com allowlist de syscalls e, no modo serviço, unidade systemd com `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, `MemoryDenyWriteExecute=yes` e `RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_PACKET AF_INET AF_INET6`.

### 18.4 Memória

- A baseline decifrada, a chave de sessão e a passphrase ficam em memória bloqueada (`mlock`) e são zeradas ao sair.
- Core dumps são desabilitados (`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`).

### 18.5 Superfície de ataque

- O parser de pacotes só decodifica o necessário (IP, UDP/TCP, DNS, cabeçalho STUN, mDNS) e tem fuzzing contínuo (`go test -fuzz`).
- O perfil YAML é validado por schema antes de qualquer uso; caminhos são canonizados.
- Nenhuma execução de comandos externos (`exec`) nos caminhos críticos: tudo via syscalls e netlink.

---

## 19. Stack técnica

| Área | Escolha | Observação |
|---|---|---|
| Linguagem | Go ≥ 1.23 | Binário único, cross-compile, runtime embutido |
| Captura | `github.com/gopacket/gopacket` (`afpacket`, `layers`) + `golang.org/x/net/bpf` | Ring TPACKET_V3, filtro BPF no kernel |
| Netlink | `github.com/vishvananda/netlink` | Links, endereços, rotas, regras, subscriptions |
| nftables | `github.com/google/nftables` | Pure Go, transações atômicas |
| NFLOG | `github.com/florianl/go-nflog` | Tentativas bloqueadas (NET-002) |
| WireGuard | `golang.zx2c4.com/wireguard/wgctrl` | Peers, endpoints, handshake, fwmark |
| Tor | `github.com/cretz/bine` (só o controle) | Control port, cookie auth |
| DNS | `github.com/miekg/dns` | Decodificação e checks ativos |
| D-Bus | `github.com/godbus/dbus/v5` | systemd-resolved, NetworkManager, timedated, notificações |
| /proc | `github.com/prometheus/procfs` | Sockets, processos, cgroups |
| inotify | `github.com/fsnotify/fsnotify` | Arquivos de configuração |
| Geo/ASN offline | `github.com/oschwald/maxminddb-golang` + DB-IP Lite (CC BY 4.0) embutido | Sem consultas de geolocalização na rede |
| Cifra | `filippo.io/age` | Baseline, logs |
| Assinatura | `crypto/ed25519` (stdlib) | Log de sessão |
| CLI | `github.com/spf13/cobra` | |
| YAML e schema | `github.com/goccy/go-yaml` + `github.com/santhosh-tekuri/jsonschema` | |
| TUI | `github.com/charmbracelet/bubbletea` | |
| GUI | **Fyne** (`fyne.io/fyne/v2`) — alternativa: Wails | Fyne não depende de WebKit, o que facilita a distribuição |
| Bandeja | `fyne.io/systray` (StatusNotifierItem) | |

### 19.1 Estrutura do repositório

```
opsecmon/
├── cmd/
│   ├── opsecmon/          # CLI (+ modo portátil)
│   └── opsecmon-gui/      # GUI Fyne
├── internal/
│   ├── daemon/            # orquestração, estado, sessão
│   ├── discovery/         # túnel, interfaces, endpoints, DNS
│   ├── sensors/           # afpacket, netlink, nflog, procfs, dbus, inotify
│   ├── checks/            # net/, dns/, tun/, host/, persona/, self/
│   ├── engine/            # severidade, dedup, estado global
│   ├── response/          # ações
│   ├── guard/             # tabelas nftables
│   ├── baseline/
│   ├── profile/           # schema + validação
│   ├── journal/           # log encadeado, age, ed25519
│   ├── report/
│   ├── ipc/               # JSON-RPC sobre Unix socket
│   ├── selftest/
│   └── geo/               # mmdb embutido
├── assets/                # ícones, sons, mmdb, schema
├── packaging/             # deb, rpm, systemd unit
├── test/
│   ├── e2e/               # cenários em network namespaces
│   └── fuzz/
└── docs/
```

---

## 20. Requisitos não funcionais

| Requisito | Meta |
|---|---|
| Latência de detecção (NET-001, DNS-001, NET-003) | ≤ 1 s entre o pacote e o evento (alvo: ≤ 200 ms) |
| Latência de `block_all` após a detecção | ≤ 200 ms |
| Latência até o alerta em tela cheia | ≤ 500 ms |
| Tempo do `run` até ARMADO | ≤ 10 s (sem contar a passphrase) |
| CPU do daemon (em repouso / 100 Mbit/s no túnel) | < 1 % / < 3 % de um núcleo |
| Memória do daemon | < 150 MB RSS |
| Tamanho do binário | < 40 MB (CLI + daemon); GUI separada |
| Perda de pacotes na captura | 0 em até 1 Gbit/s na interface física (o filtro BPF descarta o permitido no kernel) |
| Conexões próprias de rede | Zero, exceto checks ativos habilitados (verificado no CI) |
| Resíduos após `disarm` ou `cleanup` | Zero tabelas nftables, zero arquivos fora de `storage.dir` |

---

## 21. Critérios de aceitação

A v1 está pronta quando, nas distribuições do §4.1:

1. **Vazamento básico:** com WireGuard ativo e `guard: off`, `curl --interface <física> http://192.0.2.1` gera NET-001 CRITICAL em ≤ 1 s, com o processo `curl` atribuído.
2. **DNS:** `dig @192.0.2.53 teste.example` pela interface física gera DNS-001 CRITICAL com o nome consultado registrado (cifrado).
3. **IPv6:** em rede com IPv6 nativo e túnel só v4, NET-003 CRITICAL aparece no `arm`.
4. **Queda do túnel:** `ip link set wg0 down` gera TUN-001 CRITICAL; no modo estrito nenhum pacote sai pela interface física (verificado por captura externa).
5. **Troca de servidor:** o cliente VPN troca de endpoint; o allowlist é atualizado em ≤ 1 s, sem falso positivo além de um NET-002 opcional.
6. **Kill switch alterado:** apagar a tabela nftables do cliente VPN gera TUN-004 CRITICAL.
7. **Tor:** com Tor Browser aberto, a descoberta identifica o control port 9151 e os guards; se o Tor for parado, TUN-003 aparece.
8. **Pânico:** `opsecmon panic` bloqueia todo o tráfego em ≤ 200 ms; `unpanic` só libera depois do re-check.
9. **Crash do daemon em modo estrito:** `kill -9` no daemon; a tabela permanece e nenhum tráfego vaza; `opsecmon cleanup` remove tudo.
10. **Integridade:** alterar um byte de qualquer segmento do log faz `opsecmon verify` falhar com código 4.
11. **Selftest:** todos os casos do §17.2 passam numa instalação limpa.
12. **Sem comunicação própria:** a suíte e2e roda em namespace isolado sem nenhuma conexão inesperada.
13. **Sem resíduos:** depois do `disarm`, `nft list ruleset` é idêntico ao de antes do `arm`.

---

## 22. Limitações conhecidas

1. **Host comprometido:** malware com root pode cegar o daemon, alterar a captura ou matar o processo. No modo estrito a tabela permanece (fail-closed), mas a ferramenta não garante nada contra um adversário com root local. Mitigação futura: modo sensor num dispositivo separado (§23).
2. **Modo reativo vaza o primeiro pacote:** ele só detecta depois. Por isso o recomendado é o modo estrito.
3. **Atribuição de processo por /proc é melhor esforço:** conexões UDP curtas podem terminar antes da varredura. O evento de vazamento é registrado mesmo assim, com `proc.confidence: none`. A atribuição exata no momento do `connect` fica para a v1.1 (eBPF).
4. **Vazamentos dentro do túnel não são vazamentos de IP:** um documento-beacon aberto passa pelo túnel e revela o IP da VPN, não o real, mas revela atividade e horário. A recomendação é abrir arquivos de alvos em VM offline (checklist).
5. **Fingerprint do navegador** não é avaliado na v1.
6. **Wayland:** o alerta em tela cheia pode não tomar o foco em alguns compositores (§15.4).
7. **A base geográfica offline envelhece:** ela é atualizada a cada release, e a data da base aparece no `version` e no relatório.
8. **Reboot remove o guarda:** intencional; exige um novo `arm`.

---

## 23. Roadmap

### v1.0 — MVP (Linux)
Tudo o que está especificado acima, exceto DNS-005.

### v1.1
- Atribuição de processo via eBPF (`cgroup/connect4`, `connect6`, `sendmsg4/6`) com confiança alta mesmo para conexões curtas.
- DNS-005 (canário de DNS) + componente servidor autoritativo mínimo para a instituição.
- Unidade de atalho global para pânico.

### v1.2
- Extensão de navegador (Firefox e Tor Browser) para checks de fingerprint coerentes com a persona (timezone JS, idioma, WebRTC efetivo, canvas e WebGL).
- Perfis de persona múltiplos por máquina.

### v2.0
- **Modo sensor:** o mesmo binário rodando num dispositivo em linha (Raspberry Pi, mini-PC) entre a máquina do operador e a rede, enviando eventos para a GUI por canal autenticado (WireGuard ponto a ponto). Fecha a limitação 22.1.
- Windows (Npcap ou ETW para captura, WFP para o guarda).
- macOS (pf anchors, Network Extension).

---

## 24. Questões em aberto

1. **Nome definitivo** da ferramenta.
2. **GUI:** Fyne (menos dependências) ou Wails (UI mais rica, depende de WebKitGTK)?
3. **Chaves institucionais:** os logs devem ser cifrados para uma chave pública da instituição e a chave de sessão assinada por uma CA interna? Quem custodia a chave privada?
4. **Política de `--force`:** quem pode armar com o preflight falhando, e se isso exige uma segunda pessoa (regra de dois).
5. **Endpoints dos checks ativos:** usar serviços públicos (Tor Project, provedores VPN) ou um endpoint próprio da instituição? O endpoint próprio evita terceiros, mas, se for exclusivo da instituição, pode servir de assinatura que liga personas diferentes entre si.
6. **Retenção:** por quanto tempo os logs e relatórios ficam guardados e onde, alinhado à política da instituição e aos requisitos de prova.
7. **Nível do checklist manual:** obrigatório a cada sessão ou só na primeira sessão de cada persona.