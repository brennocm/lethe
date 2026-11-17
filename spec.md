# lethe — Especificação Técnica v1 (Linux)

> Monitor local de OpSec para operações de investigação/CTI: detecta, registra e reage a vazamentos de IP, DNS e identidade durante toda a operação.

| Campo | Valor |
|---|---|
| Versão do documento | 0.2 (revisada para execução por agente de código) |
| Data | 2026-11-15 |
| Plataforma v1 | Linux (x86_64 e arm64) |
| Nome | `lethe` (binários `lethe` e `lethe-gui`; antes chamado `opsecmon`) |
| Status | Pronto para implementação (decisões padrão em §25; revisáveis por ADR) |
| Versão anterior | `docs/archive/spec-v0.1.md` |

---

## Como ler este documento

- **Parte I (§1–§22)** diz **o que** construir. **Parte II (§23–§27)** diz **em que ordem** e **como provar** que está pronto. A Parte III tem os apêndices: ferramentas parecidas, correções feitas em relação à v0.1 e glossário.
- As palavras **DEVE**, **NÃO DEVE**, **DEVERIA** e **PODE** seguem a RFC 2119. Um agente de código trata DEVE como requisito testável e DEVERIA como padrão, que só pode ser descartado com um ADR.
- Toda lacuna que esta spec não resolve segue a §25 (decisões padrão). Se nem ela resolver, o agente **escolhe a opção mais restritiva (fail-closed), registra a escolha em `docs/adr/` e continua**, sem parar para perguntar.
- IDs (`NET-001`, `ST-NET-001`, `AC-04`, `M5`) são estáveis: aparecem no código, nos testes e nos commits.

## Sumário

**Parte I — Produto**
1. [Visão geral](#1-visão-geral)
2. [Modelo de ameaça](#2-modelo-de-ameaça)
3. [Princípios de design](#3-princípios-de-design)
4. [Escopo da v1 e requisitos de sistema](#4-escopo-da-v1-e-requisitos-de-sistema)
5. [Arquitetura](#5-arquitetura)
6. [Ciclo de vida de uma operação](#6-ciclo-de-vida-de-uma-operação)
7. [Descoberta automática do ambiente](#7-descoberta-automática-do-ambiente)
8. [Sensor de captura (NET-001)](#8-sensor-de-captura-net-001)
9. [Catálogo de checks](#9-catálogo-de-checks)
10. [Severidade, estados e respostas](#10-severidade-estados-e-respostas)
11. [Modo guarda (nftables)](#11-modo-guarda-nftables)
12. [Linha de base (baseline)](#12-linha-de-base-baseline)
13. [Perfil de operação](#13-perfil-de-operação)
14. [Log, relatório e cadeia de custódia](#14-log-relatório-e-cadeia-de-custódia)
15. [CLI](#15-cli)
16. [GUI e TUI](#16-gui-e-tui)
17. [IPC](#17-ipc)
18. [Autoteste (selftest)](#18-autoteste-selftest)
19. [Segurança da própria ferramenta](#19-segurança-da-própria-ferramenta)
20. [Stack técnica e repositório](#20-stack-técnica-e-repositório)
21. [Requisitos não funcionais](#21-requisitos-não-funcionais)
22. [Limitações conhecidas](#22-limitações-conhecidas)

**Parte II — Execução**
23. [Estratégia de testes](#23-estratégia-de-testes)
24. [Plano de implementação (marcos)](#24-plano-de-implementação-marcos)
25. [Decisões padrão (antes "questões em aberto")](#25-decisões-padrão-antes-questões-em-aberto)
26. [Critérios de aceitação da v1](#26-critérios-de-aceitação-da-v1)
27. [Roadmap pós-v1](#27-roadmap-pós-v1)

**Parte III — Apêndices**
- [A. Ferramentas existentes e o que reaproveitar](#apêndice-a--ferramentas-existentes-e-o-que-reaproveitar)
- [B. Correções em relação à v0.1](#apêndice-b--correções-em-relação-à-v01)
- [C. Glossário](#apêndice-c--glossário)

---

# Parte I — Produto

## 1. Visão geral

### 1.1 Problema

O operador trabalha atrás de VPN e/ou Tor, mas o anonimato depende de dezenas de detalhes que falham em silêncio: o túnel cai, o kill switch do cliente VPN não cobre todas as interfaces, o IPv6 sai por fora, o DNS volta para o resolvedor do provedor, um app se liga direto à interface física, a máquina entra numa rede Wi-Fi nova, um cliente de sincronização se conecta com a conta pessoal. Na maioria dos casos, o operador só fica sabendo depois, se ficar.

### 1.2 Solução

O `lethe` é **instalado na hora**, em cima do ambiente que o operador já usa. Ele não substitui o cliente VPN nem o Tor. Ele:

1. **Descobre** o ambiente: túnel, endpoints, interfaces de saída e DNS.
2. **Verifica** antes de começar (preflight).
3. **Monitora** continuamente durante a operação.
4. **Reage** sozinho a eventos críticos, com alerta forte e, se configurado, bloqueio.
5. **Registra** tudo num log cifrado, encadeado e assinado, que serve de registro operacional e de cadeia de custódia.

### 1.3 Regra central

> **Numa interface de saída (§7.2), só pode sair tráfego destinado ao endpoint do túnel, mais uma lista fechada de exceções de enlace (DHCP, ARP, NDP, EAPOL). Qualquer outra coisa é vazamento.**

DNS, IPv6, WebRTC, NTP e mDNS são subclassificações dessa regra ou verificações de coerência em volta dela.

### 1.4 Objetivos

- Detectar vazamento de IP e de DNS em até **1 s** (alvo: 200 ms).
- Funcionar com os túneis comuns (WireGuard, OpenVPN, Tor e clientes comerciais) **sem configuração manual** na maioria dos casos.
- Não alterar o sistema de forma permanente: tudo o que a ferramenta muda é revertido no desarme ou com `lethe cleanup`.
- Não ser, ela mesma, uma fonte de vazamento.
- Produzir um registro verificável da sessão.

### 1.5 Não objetivos (v1)

- Não é um sistema operacional nem substitui Whonix, Qubes ou Tails.
- Não é cliente VPN nem cliente Tor.
- Não protege contra o host comprometido com root (§22).
- Não testa o fingerprint do navegador (isso exige uma extensão; §27).
- Não cobre Windows nem macOS.
- Não inspeciona o conteúdo do tráfego que passa **dentro** do túnel (§27, IDN-001).

---

## 2. Modelo de ameaça

### 2.1 Adversário

Grupo criminoso com capacidade técnica alta, interesse em identificar e localizar o investigador e disposição para violência física.

**Capacidades presumidas:**

- Opera sites, fóruns, painéis, servidores e canais que o operador visita, e vê o IP de origem, o resolvedor DNS, os candidatos WebRTC, o fingerprint do navegador e os horários.
- Envia links e arquivos com beacons (canary tokens, documentos que "ligam para casa").
- Pode comprometer o navegador do operador por meio de conteúdo malicioso, ganhando execução de código **com o UID do operador**, mas sem root. *(Capacidade acrescentada na v0.2; motiva a §17.3.)*
- Correlaciona identidades entre plataformas (usernames, horários, estilo).
- Compra dados vazados ou de corretores (dados de provedores, geolocalização por IP).

**Capacidades não presumidas:** adversário em nível de Estado, controle do provedor do operador, correlação global de tráfego sobre o Tor, root local.

### 2.2 Cobertura

| Ameaça | Cobertura v1 |
|---|---|
| Queda ou falha do túnel com tráfego saindo pela interface física | ✅ Detecta (≤ 1 s) e, no modo guarda estrito, impede |
| DNS resolvido fora do túnel | ✅ |
| IPv6 fora do túnel | ✅ |
| WebRTC/STUN fora do túnel | ✅ (pela regra central) |
| App ligado diretamente à interface física | ✅ com atribuição de processo (melhor esforço) |
| Troca de rede, interfaces novas, tethering USB | ✅ |
| Kill switch do cliente VPN alterado ou removido | ✅ (nftables; iptables-legacy só gera aviso de visibilidade, TUN-007) |
| Incoerência da persona (IP de saída × timezone × idioma) | ✅ |
| Processos que revelam identidade (sync, mensageiros) | ✅ por lista de negação |
| Broadcasts na LAN com hostname (mDNS, LLMNR, NetBIOS, DHCP) | ✅ |
| Serviço de geolocalização do sistema enviando BSSIDs pelo túnel | ✅ (HOST-009) |
| Processo do operador (browser comprometido) tentando desarmar a ferramenta | ✅ (ações sensíveis exigem passphrase, §17.3) |
| Fingerprint do navegador | ❌ v1.2 |
| Vazamento de identidade dentro do túnel (login pessoal, SNI) | ❌ v1.1 (IDN-001) |
| Malware com root no host | ❌ fora do escopo |
| Correlação comportamental (horário, estilo, reuso de nomes) | ⚠️ checklist manual no preflight |

---

## 3. Princípios de design

1. **Fail-closed onde for possível; nunca fail-silent.** Se a ferramenta não consegue ver, o estado é **CINZA (visibilidade degradada)**, nunca verde. "Não sei" ≠ "seguro". Interface nova e ainda não classificada é tratada como interface de saída.
2. **Detecção passiva primeiro.** Checks ativos (consultar o IP de saída, por exemplo) são complementares, opcionais e passam só pelo túnel.
3. **Nenhum efeito colateral permanente.** Toda regra fica em tabelas nftables próprias (prefixo `lethe`); todo arquivo fica em `storage.dir` ou em `$RUNTIME_DIR/lethe`. `lethe cleanup` remove tudo.
4. **Menor privilégio.** O daemon fica com um conjunto mínimo de capabilities. Tudo o que depende da sessão do usuário (D-Bus de sessão, PipeWire, notificações) roda num processo separado com o UID do operador (§5.1).
5. **A ferramenta não fala com a internet por conta própria:** sem telemetria, sem verificação de updates, sem download de bases. Tudo o que ela precisa vem embutido. As únicas exceções são os checks ativos habilitados e o `baseline create` em modo online.
6. **Tudo é registrado.** Cada check, alerta, ação, reconhecimento do operador e mudança de estado vira evento no log encadeado.
7. **Alertas que não passam despercebidos.** Alerta crítico abre em tela cheia (melhor esforço), com notificação crítica e som; não fecha com Esc.
8. **Testável.** Cada detector tem um caso de autoteste que comprova que ele funciona naquela máquina, naquele momento, e um teste e2e em network namespace no CI.
9. **Dados de baixa confiança só elevam a severidade.** O que vem do processo de sessão (mesmo UID do navegador) pode abrir alertas, mas nunca fechar nem rebaixar alertas.
10. **Sem `exec` de comandos externos.** Tudo passa por syscalls, netlink e D-Bus. A única exceção é o próprio binário (`/proc/self/exe`) re-executado para separar privilégios.
11. **Ajudar, não atrapalhar o operador.** Quem usa o lethe é investigador, não especialista em firewall. O bloqueio fica onde impede um vazamento, mas nenhum erro de configuração pode trancar a rede em silêncio: todo estado de bloqueio diz, em linguagem simples, o que aconteceu, por quê e o comando exato para sair; o que tranca a rede é difícil de ativar por engano (§10.6).

---

## 4. Escopo da v1 e requisitos de sistema

### 4.1 Distribuições alvo

| Distribuição | Versões | Kernel típico | Observação |
|---|---|---|---|
| Debian | 12, 13 | 6.1 / 6.12 | — |
| Ubuntu | 22.04, 24.04, 26.04 | 5.15 (GA) ou 6.x (HWE) / 6.8 / 6.x | 22.04 GA não tem hook `netdev egress` (§11.5) |
| Fedora | as duas versões suportadas | 6.x | — |
| Kali Linux | rolling | 6.x | — |

Ambiente de desenvolvimento: WSL2 serve para unit tests e e2e em namespaces; não serve para testes com Wi-Fi, NetworkManager ou GUI.

### 4.2 Requisitos

- Kernel ≥ 5.10; ≥ 5.16 para a camada `netdev egress` (§11.5).
- nftables disponível no kernel. O binário `nft` **não** é necessário: a ferramenta fala netlink diretamente.
- cgroup v2 (unificado).
- systemd **DEVERIA** existir (resolved, logind, unidade opcional). Sem systemd, as fontes correspondentes ficam marcadas como "indisponível" e os checks dependentes vão para CINZA, em vez de falhar.
- Execução como root (via `sudo`), com descarte imediato para o conjunto de capabilities da §19.3.
- Desktop opcional: GNOME, KDE, XFCE; X11 e Wayland (com as ressalvas da §16.4).

### 4.3 Túneis suportados na v1

| Tipo | Descoberta | Observações |
|---|---|---|
| WireGuard (kernel e wireguard-go) | Interface + `wgctrl` (peers, endpoints, último handshake, fwmark) | Inclui wg-quick e NetworkManager |
| OpenVPN | Interface `tun*`/`tap*` + sockets do processo `openvpn` (sock_diag) | Management interface: fora da v1 |
| Tor (tor do sistema ou do Tor Browser) | Control port 9051/9151 (cookie ou senha) | Guards e bridges viram o allowlist. Transportes plugáveis: §7.5 |
| Clientes comerciais (Mullvad, Proton, IVPN etc.) | Interface + sockets do processo do serviço + cgroup | Sem integração específica, só detecção genérica |
| VPN → Tor, Tor sobre VPN | Combinação dos anteriores | O túnel mais externo define o allowlist da interface de saída |
| VMs no host (Whonix, VMs de análise) | Pela interface de saída do host | Com VPN no host, o tráfego da VM é roteado para o túnel. Tor só dentro da VM (Whonix-Gateway) sem VPN no host **não** é suportado no modo estrito (§22) |

### 4.4 Formas de distribuição

- **Modo portátil:** um binário estático `lethe` (CLI, daemon e agente de sessão), mais o binário opcional `lethe-gui`, rodando de qualquer pasta, com config e logs num diretório escolhido pelo operador (de preferência, um volume cifrado).
- **Pacote:** `.deb` e `.rpm`, com unidade systemd opcional `lethed.service`.

---

## 5. Arquitetura

### 5.1 Processos

```
                         ┌──────────────────────────────────────────────────────┐
                         │ lethe daemon  (uid 0, caps mínimas, seccomp)         │
                         │                                                      │
                         │  Discovery ─┐  Sensores ─┐  Checks ativos ─┐         │
                         │             ▼            ▼                 ▼         │
                         │         Motor de checks (registry estático) ──► Event│
                         │                          ▼                           │
                         │   Engine: dedup, alertas, estado global (puro)       │
                         │          ▼                         ▼                 │
                         │   Journal (cifrado, encadeado)   Respostas ─► Guard  │
                         │                                         (nftables)   │
                         │   Servidor IPC (Unix socket, SO_PEERCRED, papéis)    │
                         └───────────▲──────────────────▲──────────────▲────────┘
                                     │                  │              │
                ┌────────────────────┴───┐   ┌──────────┴─────┐  ┌─────┴──────────┐
                │ lethe agent (uid oper.) │   │ lethe (CLI/TUI) │  │ lethe-gui       │
                │ D-Bus de sessão,        │   │ uid operador    │  │ uid operador    │
                │ notificações, PipeWire, │   └────────────────┘  └────────────────┘
                │ portal, teclado, LANG   │
                └─────────────────────────┘
```

| Processo | Responsabilidade | Privilégio |
|---|---|---|
| `lethe daemon` | Descoberta, sensores, checks de sistema, estado, respostas, log, guarda | uid 0 → capabilities mínimas (§19.3) |
| `lethe agent` | Checks e ações que dependem da sessão gráfica: notificações (`org.freedesktop.Notifications`), som, capturas no PipeWire, sessões de screencast do portal, layout de teclado, `LANG` da sessão | UID do operador. Iniciado pelo `run` (fork + setuid antes de descartar as caps) ou pela sessão do usuário no modo serviço |
| `lethe` (CLI/TUI) | Comandos do operador; no modo portátil, sobe o daemon em primeiro plano | usuário; sobe para root só no `run` |
| `lethe-gui` | Bandeja, painel e alerta em tela cheia | UID do operador |

O agente de sessão é um **sensor de baixa confiança** (princípio 9): roda com o mesmo UID do navegador, então pode ser manipulado. Se ele para de responder, o daemon emite SELF-003 e o estado vai para CINZA.

### 5.2 Modos de execução

| Modo | Como | Uso |
|---|---|---|
| Portátil (padrão) | `sudo ./lethe run -p op.yaml`: sobe o daemon em primeiro plano, re-executa a si mesmo como `SUDO_UID` para o agente e abre a GUI (ou a TUI, com `--tui`). A GUI é o `lethe-gui` ao lado do binário; quem a abre é o agente, pedindo ao systemd do usuário (D-Bus, `StartTransientUnit`) uma unidade transitória, porque o lethe não executa outros programas (princípio 10). Sem `lethe-gui` ou sem systemd de usuário, os alertas ficam nas notificações do agente e no terminal | Instalação na hora |
| Serviço | `lethed.service` + `lethe arm/disarm`; o agente sobe por unidade de usuário (`lethe-agent.service`, `systemctl --user`) | Máquinas dedicadas |

### 5.3 Fluxo de dados e camadas de código

```
Sensores (I/O)  →  Observation (fato bruto, tipado)
Checks          →  Event {check, severity, data, source, confidence}
Engine (puro)   →  Alert lifecycle + GlobalState + ResponsePlan
Responses (I/O) →  executa o plano; o resultado volta como Event (response.executed)
Journal         →  persiste todo Event e toda transição
```

- `internal/engine` é **puro**: não faz I/O, não lê relógio (recebe um `Clock`) e é 100% testável por tabela. Toda regra de severidade, deduplicação, precedência de cor e máquina de estados da sessão fica nele.
- Sensores nunca decidem severidade. Checks nunca executam respostas.

### 5.4 Interface de check

```go
type Kind uint8 // Passive | Active | Preflight

type Check interface {
    ID() string                       // "NET-001"
    Kind() Kind
    DefaultSeverity() Severity
    Sources() []SourceID              // sensores de que depende; se algum cair → CINZA
    Start(ctx context.Context, env Env, out chan<- Event) error
    Reconfigure(env Env) error        // chamado quando a descoberta muda
    Evaluate(ctx context.Context, env Env) ([]Event, error) // passada única (preflight)
    SelfTestCases() []string          // IDs ST-* que cobrem este check
}
```

Na implementação (ADR 0004), a interface carrega só os metadados (`ID`, `Kind`, `DefaultSeverity`, `Sources`, `SelfTestCases`) e cada check expõe um avaliador puro e tipado; o daemon é dono dos sensores e chama os avaliadores. Os checks são registrados estaticamente num `registry` (sem carregamento dinâmico de código). A severidade e as ações de cada check podem ser sobrescritas pelo perfil, mas **nunca para baixo de WARNING** quando o check padrão é CRITICAL, a menos que o perfil tenha `overrides_allow_downgrade: true`, o que gera um aviso no preflight.

---

## 6. Ciclo de vida de uma operação

### 6.1 Máquina de estados da sessão

```
 [SEM BASELINE] ──baseline create──▶ [PRONTO] ──preflight OK──▶ [VERIFICADO]
                                        ▲                             │ arm
                                        │ disarm                      ▼
                                        │                        ┌─────────┐
                                        └─────────────────────── │ ARMADO  │◀──┐
                                                                 └────┬────┘   │ unpanic
                                                       CRITICAL em    │        │ (re-check OK
                                                       guarda strict, │        │  + passphrase)
                                                       ou panic manual▼        │
                                                                 ┌─────────┐   │
                                                                 │ PÂNICO  │───┘
                                                                 └─────────┘
```

Transições inválidas (por exemplo, `arm` em PRONTO sem preflight) retornam erro tipado. A única exceção é `arm --force --reason`, que fica registrada. O `--force` nunca passa por cima de uma falha de túnel quando o guarda é `strict` ou `reactive` (§10.6). A tabela de transições DEVE estar em `internal/engine/session.go` e ser testada exaustivamente (todas as combinações estado × comando).

Dentro de **ARMADO** e **PÂNICO**, o estado global é a cor:

| Cor | Significado |
|---|---|
| 🟢 VERDE | Todos os checks passam e todas as fontes estão vivas |
| 🟡 AMARELO | Há WARNING aberto |
| 🔴 VERMELHO | Há CRITICAL aberto |
| ⚪ CINZA | Visibilidade degradada: um sensor caiu, perdeu pacotes, o túnel não foi identificado ou o agente de sessão sumiu |

Precedência: **VERMELHO > CINZA > AMARELO > VERDE**.

### 6.2 Fases

1. **Baseline** (antes da operação, em rede conhecida): captura a identidade real (§12).
2. **Preflight**: checks PF, passada única dos P e checklist humano (§9.8). Falha crítica bloqueia o `arm`, a menos que se use `--force --reason "..."`, o que fica registrado.
3. **Arm**: decifra a baseline, inicia os sensores, aplica o guarda (se habilitado), gera a chave de sessão, abre o log e mostra a impressão digital da chave de sessão (§14.3). No modo estrito, o arm só se completa depois que o túnel prova que passa tráfego com o guarda aplicado (janela de confirmação, §10.6); sem essa prova, o guarda é removido e a sessão não fica armada.
4. **Execução**: monitoramento contínuo, alertas e respostas.
5. **Pânico** (automático ou manual): bloqueio total, encerramento dos processos configurados, alerta em tela cheia.
6. **Unpanic**: exige reconhecimento dos CRITICAL abertos, nova rodada dos checks de estado e passphrase (§10.5).
7. **Disarm**: remove o guarda, fecha e assina o log, gera o relatório.
8. **Cleanup** (opcional): remove qualquer resto (tabelas nftables, sockets, arquivos temporários).

---

## 7. Descoberta automática do ambiente

Roda no `arm` e de novo a cada evento netlink de link, endereço, rota ou regra (com debounce de 100 ms) e a cada 5 s, como rede de segurança.

### 7.1 O que é descoberto

| Item | Fonte |
|---|---|
| Interfaces e topologia | netlink (`RTM_NEWLINK`): tipo de link, `IFLA_LINK`/`IFLA_MASTER` (vlan, macvlan, bond, bridge), `/sys/class/net/*/device` |
| Interfaces de túnel | Tipo de link (`wireguard`, `tun`, `tap`) + nomes conhecidos (`wg*`, `tun*`, `proton*`, `mullvad*`, `nordlynx`, `tailscale*` etc.) |
| Endpoints do túnel | WireGuard: `wgctrl` (endpoint IP:porta de cada peer). OpenVPN e clientes comerciais: sockets UDP/TCP do processo do cliente, via sock_diag. Tor: §7.5 |
| Marca e cgroup do túnel | fwmark do WireGuard; cgroup v2 do serviço VPN (`/proc/<pid>/cgroup`) |
| Rotas e policy routing | netlink (rotas, regras, tabelas); `RTM_GETROUTE` para destinos de teste |
| DNS efetivo | `/etc/resolv.conf` (seguindo o symlink); systemd-resolved via D-Bus (`org.freedesktop.resolve1`: DNS por link, `DefaultRoute`, domínios `~.`); NetworkManager via D-Bus |
| IPv6 | Endereços globais por interface, rotas default v6, `disable_ipv6` por interface |
| Rede Wi-Fi atual | NetworkManager D-Bus (SSID, BSSID) ou nl80211 |
| Firewall legado | `/proc/net/ip_tables_names` e `/proc/net/ip6_tables_names` (TUN-007) |

### 7.2 Classificação das interfaces

Toda interface recebe **exatamente uma** classe, decidida nesta ordem:

| Ordem | Classe | Regra |
|---|---|---|
| 1 | `loopback` | `lo` |
| 2 | `override` | Listada em `network.egress_ifaces` ou `network.internal_ifaces` no perfil (usado em testes e em casos exóticos) |
| 3 | `tunnel` | Tipo `wireguard`/`tun`/`tap` ou nome conhecido de túnel |
| 4 | `egress` | Tem `/sys/class/net/<if>/device` (hardware) **ou** é vlan/macvlan/ipvlan/bond sobre uma interface `egress` **ou** é bridge com uma porta `egress` |
| 5 | `internal` | Virtual sem caminho para hardware (`veth`, `dummy`, bridge sem porta física, `docker0`, `virbr*`) |
| 6 | `unknown` | Qualquer outra. **Tratada como `egress`** pelo guarda e pelo sensor até ser classificada (princípio 1) |

O sensor de captura (§8) se liga às interfaces `egress` **de hardware** (as folhas físicas). Assim, ele vê também o tráfego que sai de vlans, bonds e bridges montadas sobre elas.

### 7.3 Modo aprendizado

Se o endpoint do túnel não puder ser determinado:

1. O estado fica **CINZA** e o evento `discovery.endpoint_unknown` é emitido.
2. A GUI, a TUI ou `lethe discover --learn` mostram, por 10 s, os destinos observados saindo pela interface de saída, agrupados por processo e cgroup.
3. O operador confirma qual é o endpoint (ação sensível, exige passphrase; §17.3). A escolha é registrada no log.
4. Alternativa: declarar os endpoints no perfil (`egress.endpoints`).

### 7.4 Atualização dinâmica

Quando o cliente VPN troca de servidor ou o Tor troca de guard, o daemon atualiza o allowlist do sensor (§8) e os sets do nftables (§11) **numa única passada**, em até **1 s**, e emite `INFO discovery.endpoint_changed`.

Problema do ovo e da galinha no modo estrito: o primeiro pacote para um endpoint novo é descartado antes de o daemon saber dele. Resolução:

- **WireGuard:** o endpoint aparece no `wgctrl` assim que é configurado, antes do handshake. O daemon consulta o `wgctrl` a cada 1 s e a cada evento de link.
- **OpenVPN e clientes comerciais:** a tentativa bloqueada chega via NFLOG (NET-002) com UID e GID. Se o socket pertencer ao processo do cliente VPN descoberto (sock_diag + `/proc/<pid>`, confiança alta), o destino é adicionado automaticamente ao allowlist e é emitido `INFO discovery.endpoint_learned`. Caso contrário, continua bloqueado. "Confiança alta" aqui é o socket identificado sem ambiguidade: o socket conectado com aquela 5-tupla, ou o **único** socket UDP não conectado ligado à porta de origem (o OpenVPN sobre UDP não conecta o socket). Nada é aprendido durante o pânico, e uma sessão aprende no máximo 64 endpoints (somando os confirmados pelo operador).
- **Resolução DNS do próprio cliente VPN** (hostname do servidor antes de conectar): bloqueada por padrão. `egress.allow_vpn_client_dns: true` libera DNS para fora **apenas** do cgroup do cliente VPN, e gera aviso no preflight.

### 7.5 Tor

- Conexão no control port: `egress.tor_control` (`auto` tenta 9051 e depois 9151). Autenticação por cookie (`PROTOCOLINFO` → `AUTHENTICATE`, com o cookie lido do caminho informado; o daemon tem `CAP_DAC_READ_SEARCH`) ou senha.
- Endpoints: IP:ORPort dos guards em uso (primeiro salto de `GETINFO circuit-status`, resolvido com `GETINFO ns/id/<fp>`), mais `GETINFO entry-guards` quando disponível, mais `GETCONF Bridge`.
- Eventos assíncronos: `SETEVENTS CIRC STATUS_CLIENT GUARD` para atualizar endpoints e TUN-003 sem polling.
- **Transportes plugáveis:**
  - `obfs4` e outros com IP:porta fixos na linha `Bridge`: suportados (o endereço da linha entra no allowlist).
  - `webtunnel`: suportado; a resolução do domínio feita pelo PT aparece como DNS-001, e o perfil pode aceitá-la explicitamente (`egress.tor_pt_dns_allow: [dominio]`).
  - `snowflake` e `meek`: os destinos são dinâmicos (CDNs e pares WebRTC). **Não suportados no modo estrito na v1**: o preflight emite PF CRITICAL `TUN-008`, e só o modo observador fica disponível.
- O cliente de controle DEVE ser próprio e mínimo (`internal/discovery/torctl`, protocolo de texto), sem dependência externa.

---

## 8. Sensor de captura (NET-001)

É a peça central. Fica detalhada aqui porque a v0.1 tinha imprecisões nela.

### 8.1 Mecanismo

- Um socket `AF_PACKET`/`SOCK_RAW` por interface `egress` de hardware, ligado (`bind`) a ela, com `ETH_P_ALL`.
- Filtro **cBPF no kernel**, gerado a partir do allowlist. Ele entrega ao espaço de usuário **só os pacotes de saída que não são permitidos**:
  1. aceita somente `pkttype == PACKET_OUTGOING` (extensão `SKF_AD_PKTTYPE`; `PACKET_OUTGOING` é um tipo de pacote, não uma opção de socket);
  2. descarta ARP (`0x0806`) e EAPOL (`0x888E`, handshake WPA, senão cada rekey do Wi-Fi viraria alerta);
  3. descarta DHCPv4 (udp 68→67) e DHCPv6 (udp 546→547);
  4. descarta ICMPv6 NDP (tipos 133, 135, 136) e MLDv2 (143);
  5. descarta destino ∈ endpoints (IP, protocolo, porta);
  6. descarta destino ∈ LAN, se `network.allow_lan: true`;
  7. entrega todo o resto (snaplen de 512 bytes, o bastante para IP + UDP/TCP + DNS + STUN).
- O filtro é trocado atomicamente (`SO_ATTACH_FILTER` substitui o anterior) a cada mudança do allowlist. Na criação do socket: anexar primeiro um filtro "descarta tudo", esvaziar a fila e só então anexar o filtro real, para não processar pacotes que chegaram antes do filtro.
- Limite do cBPF: 4096 instruções. O gerador DEVE falhar de forma explícita acima de 256 endpoints (o que vai para CINZA e gera log); um mapa eBPF fica para a v1.1.
- Volume esperado no espaço de usuário: quase zero (só vazamentos). Por isso, um socket simples (sem ring TPACKET_V3) basta. A perda é medida por `PACKET_STATISTICS` a cada 1 s (SELF-002).

### 8.2 Onde o sensor enxerga, em relação ao guarda

Os taps de `AF_PACKET` veem o pacote em `dev_queue_xmit`, **depois** das hooks `output`/`postrouting` do netfilter. Consequências:

- No modo **estrito**, o vazamento barrado pelo nftables nunca chega ao sensor. Ele aparece como NET-002 (NFLOG). O NET-001 só dispara se algo passar pelo guarda, e isso é CRITICAL **e** um defeito do guarda (evento `guard.bypass_detected`).
- Pacotes enviados por **outros sockets AF_PACKET** (por exemplo, dhclient ou ferramentas raw) **não passam** pelas hooks `inet` do nftables, mas o tap os vê. Ficam cobertos pela camada `netdev egress` (§11.5).
- Sockets com `PACKET_QDISC_BYPASS` não passam pelos taps. Limitação documentada (§22).

### 8.3 Classificação dos pacotes entregues

Por ordem; o primeiro que casar vence:

| Condição | Check |
|---|---|
| dport 53 (udp/tcp) | DNS-001 (decodifica o qname) |
| dport 853 (tcp = DoT, udp = DoQ) | DNS-001 (sem qname) |
| dport 3478, 5349, 19302–19309 ou cabeçalho STUN (magic cookie `0x2112A442`) | NET-012 |
| dport 5353, 5355, 137, 138, 1900 | NET-009 (multicast/broadcast da LAN) |
| IPv6 | NET-001, subtipo `ipv6` |
| resto | NET-001 |

Todos são CRITICAL, exceto NET-009 (WARNING). O evento carrega `iface`, `proto`, `src`, `dst`, `sport`, `dport`, `len` e, quando houver, `proc` (§9.1, NET-010).

---

## 9. Catálogo de checks

Convenções: **P** = passivo, **A** = ativo, **PF** = preflight (pontual). Severidade padrão: **C** = CRITICAL, **W** = WARNING, **I** = INFO. **Fonte** = sensor de que o check depende (se cair, CINZA).

### 9.1 Rede (NET)

| ID | Nome | Tipo | Método | Sev. |
|---|---|---|---|---|
| NET-001 | **Tráfego fora do túnel** | P | Sensor da §8. Todo pacote entregue pelo filtro é vazamento | C |
| NET-002 | Vazamento bloqueado (tentativa) | P | No modo estrito, a regra final faz `log group 4242` (com limite de taxa) e `drop`. O daemon lê via NFLOG (o kernel sempre inclui `NFULA_UID`/`NFULA_GID` quando o pacote pertence a um socket local; não existe flag para isso no NFLOG) e registra a tentativa, o UID e o destino | W |
| NET-003 | IPv6 fora do túnel | P | **C:** rota default v6 numa interface `egress` quando `expect.ipv6: false` ou quando o túnel não tem rota default v6. **W:** só endereço global, sem rota | C/W |
| NET-004 | Rota efetiva fora do túnel | P | `RTM_GETROUTE` para `192.0.2.1` e `2001:db8::1` sem marca: a interface de saída precisa ser `tunnel` | C |
| NET-005 | Mudança de rota ou policy routing | P | `RTM_NEWROUTE`/`DELROUTE`/`NEWRULE`/`DELRULE` fora das tabelas do próprio túnel | W |
| NET-006 | Interface nova ou link up | P | `RTM_NEWLINK` (tethering USB, adaptador novo, Wi-Fi associando). Se a classe for `egress` ou `unknown`, W; se for `internal`, I | W/I |
| NET-007 | Mudança de rede Wi-Fi | P | SSID/BSSID mudou durante a sessão. Se o SSID estiver na baseline, C | W/C |
| NET-008 | MAC real em uso | P/PF | MAC atual = `IFLA_PERM_ADDRESS` em interface `egress` ativa | W |
| NET-009 | Broadcast na LAN com identificadores | P | Saídas para mDNS, LLMNR, NetBIOS e SSDP (§8.3); decodifica o hostname anunciado e compara com a baseline (C se bater) | W/C |
| NET-010 | Atribuição de processo e socket na interface física | P | sock_diag (`NETLINK_SOCK_DIAG`, TCP/UDP, v4/v6) a cada 1 s e sob demanda quando NET-001/NET-002 disparam; mapa inode → PID via `/proc/*/fd`. **Enriquece** NET-001/002 com `proc` e `confidence` (`high` = 5-tupla exata; `low` = só porta local; `none`). Sozinho, gera W quando há socket com IP local de interface `egress` e destino fora do allowlist sem pacote visto | W |
| NET-011 | IP de saída (verificação ativa) | A | §9.9 | C/W |
| NET-012 | STUN/WebRTC fora do túnel | P | Subclassificação do NET-001 (§8.3) | C |
| NET-013 | Checagem de conectividade presa à interface | PF | NetworkManager com `connectivity.enabled=true`: o NM faz essa checagem com o socket preso à interface (pode sair por fora). Recomenda desligar | W |
| NET-014 | DHCP envia hostname | PF | Conexões do NM com `dhcp-send-hostname=true` (padrão) ou `dhcp-hostname` = hostname da baseline: o hostname real vai para a LAN e para o roteador | W |

### 9.2 DNS (DNS)

| ID | Nome | Tipo | Método | Sev. |
|---|---|---|---|---|
| DNS-001 | DNS fora do túnel | P | Subclassificação do NET-001 (§8.3). O qname vai cifrado no campo sensível (§14.4) | C |
| DNS-002 | Resolvedor do provedor configurado | P | Resolvedores efetivos (por trás do stub `127.0.0.53`, via D-Bus do resolved e do NM) comparados com os da baseline | C |
| DNS-003 | Resolvedor em link físico com DefaultRoute | P | systemd-resolved com DNS na interface `egress` e `DefaultRoute=yes` sem `~.` no túnel | W |
| DNS-004 | Configuração de DNS alterada | P | inotify no **diretório** de `/etc/resolv.conf` e no destino do symlink (esse arquivo é substituído atomicamente, então vigiar só o arquivo perde eventos); sinais D-Bus do resolved e do NM | W |
| DNS-005 | Canário de DNS | A | Fora da v1 (§27) | — |

### 9.3 Túnel (TUN)

| ID | Nome | Tipo | Método | Sev. |
|---|---|---|---|---|
| TUN-001 | Túnel ausente ou down | P | Interface de túnel esperada sumiu ou ficou sem `IFF_UP`/`IFF_RUNNING` | C |
| TUN-002 | Handshake WireGuard velho | P | `wgctrl`: `tx_bytes` subiu nos últimos 10 s **e** o último handshake tem mais de 180 s (`REJECT_AFTER_TIME`) | W |
| TUN-003 | Tor sem bootstrap ou sem circuito | P | `status/bootstrap-phase` < 100 ou `status/circuit-established=0`; eventos `STATUS_CLIENT` | C |
| TUN-004 | Kill switch alterado | P | No `arm`, snapshot de todas as tabelas nftables **de terceiros** (hash por tabela, sem as tabelas `lethe*`); monitor netlink (`NFNLGRP_NFTABLES`) mais reamostragem a cada 5 s. Mudança = W; sumiço de uma tabela que tinha regra de drop no output = C | W/C |
| TUN-005 | Split tunneling ativo | P/PF | Regras de policy routing com exclusões por marca ou UID; cgroups de exclusão conhecidos (net_cls v1 e cgroup v2 de clientes comerciais); processos com marca de exclusão | W |
| TUN-006 | Endpoint inesperado | P | Endpoint novo fora de `egress.expect_country` ou `expect_asn` (base offline) | W |
| TUN-007 | Firewall legado invisível | PF/P | Existem tabelas iptables-legacy (`/proc/net/ip_tables_names` não vazio, com nf_tables em uso): o kill switch pode estar ali, e o TUN-004 não o enxerga | W (cinza parcial) |
| TUN-008 | Transporte plugável não suportado | PF | Tor com `snowflake`/`meek` e guarda estrito (§7.5) | C |

### 9.4 Host (HOST)

| ID | Nome | Tipo | Método | Sev. |
|---|---|---|---|---|
| HOST-001 | Processo da lista de negação | P | Varredura de `/proc` a cada 2 s. Casamento por `exe` (caminho ou basename do `/proc/<pid>/exe`), `comm` ou `cgroup`. **`comm` é truncado em 15 caracteres** (`TASK_COMM_LEN`): o validador do perfil rejeita valores de `comm` mais longos e sugere `exe` | W/C (perfil) |
| HOST-002 | Câmera ou microfone em uso | P | Daemon: `/dev/video*` e `/dev/snd/pcmC*c` abertos (via `/proc/*/fd`). Agente: streams de captura no PipeWire | W |
| HOST-003 | Compartilhamento de tela ou acesso remoto | P | Processos conhecidos (AnyDesk, TeamViewer, RustDesk, x11vnc etc.); agente: nós de screencast no PipeWire (o portal xdg não lista as sessões ativas; ADR 0009) | W |
| HOST-004 | Hostname real | PF/P | Hostname atual = hostname da baseline | W |
| HOST-005 | Timezone e locale fora do perfil | PF/P | `/etc/localtime`, `org.freedesktop.timedate1`; agente: `LANG`/`LC_*` da sessão | W |
| HOST-006 | Disco e swap sem cifra | PF | sysfs: a raiz está sobre dm-crypt (`/sys/block/dm-*/dm/uuid` começa com `CRYPT-`); swap sobre dm-crypt ou zram | W |
| HOST-007 | Sincronização de horário | PF | Configuração do timesyncd/chrony/ntpd (o tráfego em si já é coberto pelo NET-001) | I |
| HOST-008 | Redes Wi-Fi salvas com autoconnect | PF | Conexões salvas no NM com SSID da baseline e `autoconnect=true` | W |
| HOST-009 | Serviço de geolocalização ativo | PF/P | GeoClue ativo ou com clientes (D-Bus `org.freedesktop.GeoClue2`): ele manda a lista de BSSIDs próximos para um serviço de localização, o que revela a posição física **mesmo pelo túnel** | W |

### 9.5 Persona (PER)

| ID | Nome | Tipo | Método | Sev. |
|---|---|---|---|---|
| PER-001 | Coerência geográfica | P | País do IP de saída (NET-011) × timezone × locale × layout de teclado (agente; `org.freedesktop.locale1` como fallback) × `expect` do perfil | W |
| PER-002 | Configuração de navegador | PF | Firefox e Tor Browser: `prefs.js`/`user.js` (`media.peerconnection.enabled`, `media.peerconnection.ice.default_address_only`, `network.trr.mode`, `network.proxy.socks_remote_dns`). Chromium: policies em `/etc/chromium/policies/managed` e `/etc/opt/chrome/policies/managed` (`WebRtcIPHandling`) | W |
| PER-003 | Perfil pessoal do navegador | PF/P | Processo de navegador com `-profile`/`--user-data-dir` diferente de `browsers.persona_profiles`, ou com o perfil padrão | W |

### 9.6 Autodiagnóstico (SELF)

| ID | Nome | Tipo | Método | Sev. |
|---|---|---|---|---|
| SELF-001 | Sensor parado | P | Cada sensor emite heartbeat interno; ausência por mais de 3 s → CINZA | C (cinza) |
| SELF-002 | Perda de pacotes na captura | P | `PACKET_STATISTICS.tp_drops` > 0 no intervalo | W (cinza) |
| SELF-003 | Agente de sessão ou GUI desconectados | P | Sem heartbeat IPC por mais de 3 s. Sem agente, o daemon passa a alertar só pelo terminal e pelo journald (não tem acesso ao D-Bus de sessão) | W (cinza) |
| SELF-004 | Selftest desatualizado | PF | Último selftest há mais de 24 h, ou nunca rodado nesta máquina | W |
| SELF-005 | Relógio alterado | P | `timerfd` com `TFD_TIMER_CANCEL_ON_SET` (aviso do kernel quando o relógio é ajustado) + comparação entre `CLOCK_REALTIME` e `CLOCK_BOOTTIME` a cada 1 s (salto > 2 s) | I |
| SELF-006 | Tentativas de passphrase | P | 5 provas erradas em 5 min numa ação sensível (§17.3). Nos guardas `strict` e `reactive`, a resposta é o pânico; no `off`, as ações sensíveis ficam travadas por 5 min e não há bloqueio de rede (§10.6) | C |

### 9.7 Fontes e checks dependentes

| Fonte (`SourceID`) | Checks |
|---|---|
| `capture` | NET-001, NET-009, NET-012, DNS-001 |
| `nflog` | NET-002 |
| `netlink` | NET-003…008, TUN-001, discovery |
| `sockdiag` | NET-010 |
| `wgctrl` | TUN-002, endpoints WireGuard |
| `torctl` | TUN-003, endpoints Tor |
| `nftmon` | TUN-004 |
| `procscan` | HOST-001…003, PER-003 |
| `dbus-system` | DNS-002…004, NET-007, NET-013/014, HOST-005/008/009 |
| `agent` | HOST-002/003/005 (parte de sessão), PER-001 (teclado), notificações |

### 9.8 Preflight

Executa todos os **PF**, uma passada única (`Evaluate`) dos **P** e o checklist humano.

**Automático:** NET-003, NET-004, NET-008, NET-013, NET-014, DNS-002, DNS-003, TUN-001, TUN-003, TUN-005, TUN-007, TUN-008, HOST-001…009, PER-001…003, SELF-004, mais a validação do perfil.

**Manual (confirmação item a item; cada resposta vai para o log):**

- [ ] Nenhuma conta pessoal logada no navegador ou nos apps desta sessão
- [ ] O username da persona não é reutilizado de nenhuma outra identidade
- [ ] O celular pessoal não está na mesma rede, ou está em modo avião
- [ ] Os arquivos recebidos de alvos serão abertos só em VM offline
- [ ] O horário da operação não segue o padrão do expediente pessoal

O resultado é `PASS`, `WARN` ou `FAIL` (com qualquer C). `FAIL` → exit code 2.

Falhas de **túnel** (TUN-001, TUN-003 e TUN-008 em CRITICAL) não podem ser contornadas com `--force` quando o guarda é `strict` ou `reactive`: o guarda cortaria a rede na hora. A mensagem diz isso e oferece as saídas: conectar o túnel, ou armar com `--guard off` (§10.6). Com `--guard off`, o `--force` continua valendo para elas.

### 9.9 Checks ativos (NET-011)

- Intervalo aleatório uniforme em `active_checks.egress_ip.interval` (padrão 180–600 s), mais um no `arm`.
- Consulta ≥ 2 endpoints da lista. O resultado só vale se eles concordarem.
- **VPN:** o socket é preso à interface do túnel (`SO_BINDTODEVICE`), e a resolução de nomes usa um resolvedor próprio, preso ao túnel, que pergunta ao DNS daquele link. Se não houver DNS conhecido no túnel, o check é pulado com W, e o resolvedor do sistema **nunca** é usado.
  - "DNS conhecido no túnel", nesta ordem: `active_checks.tunnel_dns` do perfil, os servidores que o systemd-resolved associa ao link do túnel, e os `nameserver` do `resolv.conf` cuja rota sai pelo túnel. Endereços loopback (stubs) nunca contam: atrás deles está o resolvedor do sistema.
- **Tor:** SOCKS5 no `SocksPort` descoberto, com resolução remota (`socks5h`).
- Cabeçalhos HTTP mínimos e um User-Agent genérico e comum. Nenhum identificador da ferramenta, para que a consulta não vire assinatura capaz de ligar personas.
- País e ASN resolvidos **offline** (§20). IP ou ASN da baseline = C; país diferente de `expect_country` = W. ASN fora de `expect_asn` (quando definido) = W. Endpoints que não concordam ou falham = W.
- O IP de saída vai **selado** no evento (pode ser o da baseline); o campo casado aparece pelo nome. O `status` mostra só país, ASN (nunca um ASN da baseline), caminho e horário da última resposta concordante.
- Com o país do IP de saída, o PER-001 compara o país do timezone da máquina (`zone1970.tab` do sistema; timezone de vários países casa com qualquer um) e o território do locale. Sem base geo no binário, a parte de país do NET-011 e do PER-001 fica inativa, e o IP/ASN da baseline continua sendo verificado pelo IP.

---

## 10. Severidade, estados e respostas

### 10.1 Níveis

| Nível | Semântica | Efeito |
|---|---|---|
| INFO | Fato relevante, sem risco | Nenhum |
| WARNING | Configuração arriscada ou evento que pode virar vazamento | AMARELO |
| CRITICAL | Vazamento ocorrido ou iminente | VERMELHO + respostas |

### 10.2 Ciclo de vida do alerta

`aberto → reconhecido → resolvido` (e `aberto → resolvido` direto, quando a condição some sozinha).

- Chave de deduplicação: `(check, iface, dst, dport, proc.exe)`. Eventos com a mesma chave em menos de 5 s incrementam o contador do alerta aberto, em vez de abrir outro.
- Alertas **pontuais** (NET-001, NET-002, NET-009, NET-012, DNS-001) são resolvidos automaticamente após 10 s sem nova ocorrência. Alertas de **condição** (NET-003, TUN-001 etc.) são resolvidos quando a condição deixa de valer por ≥ 10 s.
- Um CRITICAL resolvido mas **não reconhecido** continua contando para o unpanic e aparece no relatório como "não reconhecido".
- Reconhecer um CRITICAL é ação sensível (§17.3): exige motivo e passphrase.

### 10.3 Ações de resposta

| Ação | Efeito | Executor | Latência alvo |
|---|---|---|---|
| `alert_tray` | Ícone muda de cor + notificação | agente/GUI | ≤ 200 ms |
| `alert_sound` | Som distinto por severidade | agente | ≤ 200 ms |
| `alert_fullscreen` | Janela em tela cheia, pedida acima de tudo; não fecha com Esc | GUI | ≤ 500 ms |
| `block_all` | Aplica as tabelas de pânico (§11.4) | daemon | ≤ 200 ms |
| `kill_processes` | SIGKILL nos processos que casam com `processes.kill_on_panic` | daemon | ≤ 200 ms |
| `kill_offender` | SIGKILL no processo atribuído ao evento, só com `confidence: high` | daemon | ≤ 200 ms |
| `link_down` | Derruba todas as interfaces `egress` via netlink (`IFF_UP` off) | daemon | ≤ 200 ms |
| `lock_screen` | `org.freedesktop.login1.Session.Lock` via D-Bus do sistema | daemon | ≤ 500 ms |

As ações de rede e de processo são executadas **pelo daemon**, nunca pela GUI, para que funcionem mesmo se ela travar. Cada ação gera `response.executed` com resultado e latência medida.

### 10.4 Respostas padrão

| Severidade | Guarda `off` | Guarda `reactive` | Guarda `strict` |
|---|---|---|---|
| WARNING | `alert_tray`, `alert_sound` | idem | idem |
| CRITICAL | `alert_fullscreen`, `alert_sound` | `block_all`, `kill_processes`, `alert_fullscreen`, `alert_sound` | `block_all`, `kill_processes`, `alert_fullscreen`, `alert_sound` |

NET-002 (tentativa bloqueada no estrito) é WARNING por definição: o guarda funcionou. Tudo pode ser ajustado por check no perfil (§13), respeitando a §5.4.

### 10.5 Pânico e unpanic

- **Pânico** = `block_all` ativo. Entra sozinho (CRITICAL em `reactive`/`strict`) ou por `lethe panic`, pelo botão da GUI ou pelo `p` da TUI. Entrar em pânico **não** exige passphrase.
- **Unpanic** exige, nesta ordem:
  1. todos os CRITICAL da sessão reconhecidos;
  2. nova rodada dos checks de estado (NET-003, NET-004, DNS-002, TUN-001, TUN-003) passando. Como a rede está bloqueada, só checks locais entram aqui;
  3. passphrase (§17.3).
- Com `guard.panic.keep_tunnel: true`, o pânico mantém só o túnel (igual ao estrito sem exceções de LAN). O padrão é **bloquear tudo**, inclusive o túnel.
- `guard.panic.link_down: auto | always | never` (padrão `auto` = usar `link_down` quando o kernel não tem `netdev egress`).

### 10.6 Proteção contra trancamento (princípio 11)

O bloqueio é deliberado só quando protege contra um vazamento durante a operação. Antes de a operação começar, ou quando o próprio guarda impediria o túnel de funcionar, a ferramenta prefere não armar e explicar.

**Evitar o trancamento por engano**

1. **`--force` não arma um guarda que cortaria a rede.** Com `strict` ou `reactive`, um FAIL de túnel no preflight (TUN-001, TUN-003, TUN-008) recusa o arm mesmo com `--force`, com exit code 2. A mensagem nomeia o problema e as saídas (`--guard off` ou conectar o túnel).
2. **Janela de confirmação do arm** (`guard.arm_confirm`, padrão `30s`; `0` desliga e gera WARN no preflight). No `strict`, depois de aplicar as tabelas, o daemon espera uma prova de que o túnel funciona com o guarda:
   - WireGuard: um handshake com menos de 180 s em algum peer, ou `rx_bytes` subindo no túnel;
   - Tor: `status/circuit-established=1`;
   - OpenVPN e genéricos: `rx_bytes` subindo em alguma interface de túnel (estatísticas netlink do link).

   A prova é só local, sem tráfego gerado pela ferramenta (princípio 5). Se ela não vier dentro da janela, o daemon remove o guarda (`guard.removed`, `reason: arm_unconfirmed`), fecha o log com `session.end` (`reason: arm_unconfirmed`) e a CLI sai com exit code 6, explicando o que faltou (por exemplo: "nenhum tráfego pelo túnel em 30 s; abra uma página ou ative o keepalive"). Durante a janela, a sessão já está armada e protegida; a reversão só acontece antes de o operador começar a operar, então não há vazamento de operação em curso. O estado `ARMADO` só é anunciado (`ARMADO` no terminal, cor na GUI) depois da prova.
3. **Passphrase errada no modo observador não bloqueia a rede.** O SELF-006 continua CRITICAL, mas com `guard.mode: off` a resposta é travar as ações sensíveis por 5 min, sem `block_all`. O `lethe panic` explícito continua bloqueando em qualquer modo, porque foi pedido pelo operador.
4. **O perfil gerado por `lethe profile init` e pelo `lethe setup` (§15.1) começa em `off`** com um comentário que explica como passar para `strict` depois do selftest. O `strict` continua sendo o recomendado (§11.1).

**Sempre mostrar a saída**

5. Todo estado em que a rede está bloqueada pelo lethe (pânico, guarda estrito sem túnel, tabelas `lethe*` que sobraram) é descrito no `status` (humano e `--json`, campo `lockdown`), no terminal do `run` e nas mensagens de erro, sempre com três partes: **o que** (por exemplo "a rede está bloqueada: pânico"), **por quê** (causa e alerta, sem valores da baseline) e **como sair** (o comando exato: `lethe unpanic`, `sudo lethe cleanup` ou reiniciar a máquina).
6. **`lethe status` sem daemon** não para no "daemon inacessível". Como root, ele lista as tabelas `lethe*` que sobraram (crash, `kill -9`, sessão interrompida) e diz que a rede está bloqueada por elas e que `sudo lethe cleanup` as remove. Sem root, ele diz que não consegue verificar e que `sudo lethe status` verifica.
7. `lethe cleanup` diz o que removeu e confirma que a rede voltou ao estado de antes do lethe (ou que não havia nada a remover).

**Primeiro uso guiado**

8. `lethe setup` é um assistente no terminal que cria o perfil e a baseline com perguntas simples (identificador da operação, persona, tipo de túnel detectado pela descoberta) e grava o perfil em `off`. Ele só oferece passar para `strict` depois de um `lethe selftest` aprovado nesta máquina, e então roda o preflight para mostrar o que o estrito vai permitir.
9. `lethe report` e `lethe verify` abrem o log com `--baseline FILE` (pede a passphrase e usa a `log_identity` embutida), além de `--identity`. Sem chaves institucionais, o operador lê o próprio relatório sem gerar outra chave.

---

## 11. Modo guarda (nftables)

### 11.1 Submodos

| Submodo | Comportamento | Quando usar |
|---|---|---|
| `off` (observador) | Nenhuma regra; só detecta e alerta | Onde não se pode mexer no firewall |
| `reactive` | Sem regras até um CRITICAL; então aplica `block_all`. **O primeiro pacote vazado já saiu** | Quando o allowlist não é confiável |
| `strict` (**recomendado**) | No `arm`, aplica uma tabela que só deixa sair pelas interfaces de saída o tráfego dos endpoints e as exceções de enlace. Vazamentos são **impedidos** e viram NET-002. Se o daemon morrer, a tabela fica: **fail-closed** | Depois de um selftest aprovado nesta máquina; o perfil gerado começa em `off` (§10.6) |

### 11.2 Propriedades do netfilter usadas no design

- Um `drop` em **qualquer** chain base é definitivo: um `accept` em outra tabela (a do cliente VPN, por exemplo) não o anula. Por isso, as tabelas `lethe*` só **acrescentam restrições**, não dependem da ordem nem do conteúdo das regras de terceiros e nunca as alteram.
- A recíproca também vale: um `drop` do cliente VPN continua valendo. O `lethe` nunca "libera" o que outro bloqueou.
- Regras iptables-legacy rodam em paralelo e também podem dropar; elas são invisíveis para o TUN-004 (TUN-007).
- `socket cgroupv2` resolve o caminho do cgroup para um **ID numérico no momento em que a regra é carregada**. Se o serviço VPN reiniciar, o cgroup ganha ID novo e a regra fica obsoleta. Por isso, o daemon DEVE vigiar o cgroup do cliente VPN (inotify em `cgroup.events` + varredura) e regerar a regra quando o ID mudar.

### 11.3 Tabela do modo estrito (referência normativa)

```nft
table inet lethe {
    set tunnel_ifaces   { type ifname; }
    set internal_ifaces { type ifname; }            # classe internal (§7.2)
    set endpoints4 { type ipv4_addr . inet_proto . inet_service; }
    set endpoints6 { type ipv6_addr . inet_proto . inet_service; }
    set lan4 { type ipv4_addr; flags interval; }    # preenchido só se allow_lan
    set lan6 { type ipv6_addr; flags interval; }

    chain output {
        type filter hook output priority filter - 10; policy drop;
        oifname "lo" accept
        oifname @tunnel_ifaces accept
        oifname @internal_ifaces accept
        # daqui em diante: interfaces egress e unknown (fail-closed)
        meta mark 0x0000ca6c accept                 # fwmark do WireGuard, só se descoberto
        ip  daddr . meta l4proto . th dport @endpoints4 accept
        ip6 daddr . meta l4proto . th dport @endpoints6 accept
        udp sport 68  udp dport 67  accept          # DHCPv4 (cliente via socket UDP)
        udp sport 546 udp dport 547 accept          # DHCPv6
        icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld2-listener-report } accept
        ip  daddr @lan4 accept                      # só com allow_lan
        ip6 daddr @lan6 accept
        limit rate 100/second burst 200 packets log group 4242 prefix "LETHE-BLOCK "
        drop
    }

    chain forward {
        type filter hook forward priority filter - 10; policy accept;
        oifname @tunnel_ifaces accept
        oifname @internal_ifaces accept
        limit rate 100/second burst 200 packets log group 4242 prefix "LETHE-FWD "
        drop                                        # VMs/containers em NAT saindo por fora
    }
}
```

Diferenças em relação à v0.1 (Apêndice B): política `drop` com allowlist de interfaces (a v0.1 aceitava qualquer interface fora de `phys_ifaces`, o que deixava passar interfaces novas ainda não classificadas); endpoints com protocolo na chave, sem `timeout` (o daemon remove o que sair da descoberta); DHCPv6 e MLDv2; log com limite de taxa.

Notas:

- Regras extras geradas pela descoberta: com `egress.allow_vpn_client_dns`, `socket cgroupv2 level N "<cgroup do cliente VPN>" meta l4proto udp|tcp th dport 53 accept` (§7.4, §11.2). O cgroup do cliente **nunca** é aceito por inteiro: com NetworkManager, o cliente roda em `NetworkManager.service`, e o tráfego próprio do NM (o teste de conectividade, por exemplo) sairia fora do túnel. O cliente alcança os servidores pelos sets de endpoints, como qualquer processo. Para Tor, `meta skuid <uid do tor> ip daddr . meta l4proto . th dport @endpoints4 accept` quando o tor roda com UID próprio.
- Tráfego de LAN só sai se `network.allow_lan: true`.
- VMs em **bridge** com porta física: `table bridge lethe`, com chain `forward` descartando frames IP para as portas `egress`, exceto ARP e DHCP. Gerada só quando existe bridge com porta `egress`.
- Toda a configuração é aplicada **numa única transação netlink** (`Flush` da google/nftables), e cada atualização de set também.

### 11.4 Tabelas de pânico

```nft
table inet lethe_panic {
    chain output  { type filter hook output  priority filter - 20; policy drop; oifname "lo" accept; }
    chain forward { type filter hook forward priority filter - 20; policy drop; }
    chain input   { type filter hook input   priority filter - 20; policy drop; iifname "lo" accept; }
}
```

Mais a camada `netdev` da §11.5 com política `drop` total. Tudo numa transação. Conexões já estabelecidas também são cortadas, porque não há `ct state` liberando nada.

### 11.5 Camada `netdev egress` (kernel ≥ 5.16)

Sockets AF_PACKET não passam pelas hooks `inet`. Em kernels que têm a hook `egress` da família `netdev`, o daemon DEVE adicionar:

```nft
table netdev lethe_l2 {
    chain egress_<if> {                         # uma por interface egress de hardware
        type filter hook egress device "<if>" priority -500; policy accept;
        # strict: ARP/EAPOL passam; IP só com o mesmo allowlist da inet lethe
        # (endpoints, DHCP, NDP/MLD, LAN), porque o remetente AF_PACKET não passou por ela;
        # o resto: log group 4242 prefix "LETHE-L2 " + drop (ADR 0005)
        meta protocol arp accept
        meta protocol 0x888e accept
        …allowlist IP…
        drop
    }
}
```

No pânico, a mesma tabela passa a `policy drop` (exceto se `keep_tunnel`). Sem kernel compatível: o preflight emite I "camada L2 indisponível", e o pânico usa `link_down` (`panic.link_down: auto`). Se a biblioteca não expuser a constante da hook egress, use o valor numérico `NF_NETDEV_EGRESS = 1`.

### 11.6 Remoção

- `disarm` remove `inet lethe`, `inet lethe_panic`, `netdev lethe_l2` e `bridge lethe` numa transação.
- `lethe cleanup` remove essas tabelas mesmo sem daemon rodando (depois de crash ou de reboot no meio da sessão). Ele só remove tabelas com prefixo `lethe` e nunca toca em outras.
- As tabelas **não** são persistidas: reboot as apaga. Isso é intencional e documentado: depois de um reboot, é preciso `arm` de novo antes de operar.

---

## 12. Linha de base (baseline)

### 12.1 Conteúdo

O arquivo `baseline.age` é um JSON cifrado com **age**. Dentro dele, os valores ficam **em claro**. A proteção vem da cifra do arquivo e da regra de que esses valores nunca saem dele.

| Campo | Origem |
|---|---|
| `networks[]`: IP público v4/v6, ASN, provedor, resolvedores DNS, gateway (IP e MAC), SSIDs | Uma entrada por rede conhecida (casa, escritório…), via `baseline create` e `baseline add-network` |
| `perm_macs[]` | `IFLA_PERM_ADDRESS` |
| `hostname`, `username` | sistema |
| `timezone`, `locale`, `keyboard` | sistema |
| `log_identity` | Identidade age X25519 gerada na criação; a chave pública (`log_recipient`) cifra os logs quando o perfil não define um destinatário institucional |
| `created_at`, `tool_version` | — |

*Correção em relação à v0.1:* hash salgado de IPv4, MAC, SSID ou hostname **não** protege o valor. Esses espaços são pequenos (IPv4 tem 2³²; MAC com OUI conhecido, 2²⁴), e o sal está no mesmo arquivo. A v0.2 abandona os hashes e adota uma regra mais simples e verificável: **nenhum valor da baseline aparece em evento, log, relatório ou IPC**. Um casamento é registrado só pelo nome do campo (`"matched": "baseline.networks[0].asn"`).

### 12.2 Criação

- `lethe baseline create`: precisa rodar **sem túnel**, numa rede conhecida. Ela detecta túnel ativo e se recusa sem `--allow-tunnel`. Consulta o IP público em ≥ 2 endpoints (a mesma lista dos checks ativos) e mostra o que coletou antes de cifrar.
- `lethe baseline create --manual`: nenhuma consulta de rede; o operador informa ASN, provedor, SSIDs e resolvedores.
- `lethe baseline add-network [--manual]`: adiciona outra rede conhecida.
- Cifra: passphrase (scrypt do age). O age não permite misturar passphrase com outros destinatários no mesmo arquivo; por isso, com `--recipient` (destinatário X25519 da instituição), é gerada uma **cópia de recuperação separada**, `baseline.age.recovery`, cifrada só para a instituição.
- Entrada não interativa: `--passphrase-fd N` lê a passphrase de um descritor de arquivo (para automação e testes); sem ele, a leitura é feita no terminal, sem eco.

### 12.3 Uso

O daemon decifra a baseline em memória no `arm` (pede a passphrase pelo terminal ou pela GUI via IPC) e nunca a grava em claro. A passphrase verificada fica em memória protegida (§19.4) para validar as ações sensíveis (§17.3).

---

## 13. Perfil de operação

### 13.1 Formato

YAML, validado contra um JSON Schema embutido (`internal/profile/schema.json`; `lethe profile validate`). Campos desconhecidos são **erro**, não aviso. Caminhos com `~` são expandidos para o home do operador (`SUDO_UID`) e canonizados.

### 13.2 Exemplo completo

```yaml
version: 1
operation:
  id: "OP-2026-117"
  persona: "falcao"
  operator: "agente-07"          # pseudônimo; opcional

egress:
  type: wireguard                # wireguard | openvpn | tor | vpn+tor | auto
  expect_country: NL
  expect_asn: []
  endpoints: []                  # "203.0.113.10:51820/udp" quando a descoberta não resolver
  tor_control: auto              # auto | "127.0.0.1:9151"
  tor_cookie: auto               # auto | caminho do control_auth_cookie
  tor_pt_dns_allow: []
  allow_vpn_client_dns: false

expect:
  timezone: UTC
  locale: en_US.UTF-8
  keyboard: us
  ipv6: false

network:
  allow_lan: false
  allow_dhcp: true
  egress_ifaces: []              # override da classificação (§7.2)
  internal_ifaces: []

baseline:
  file: /media/op/vault/baseline.age

guard:
  mode: strict                   # off | reactive | strict
  arm_confirm: 30s               # janela para o túnel provar que funciona com o guarda (0 = sem janela)
  panic:
    keep_tunnel: false
    link_down: auto              # auto | always | never

active_checks:
  enabled: true
  egress_ip:
    interval: [180s, 600s]
    endpoints:
      - https://check.torproject.org/api/ip
      - https://am.i.mullvad.net/json
  tunnel_dns: []               # DNS do túnel, se a descoberta não achar (nunca loopback)

processes:
  deny:
    - { match: exe,  value: onedrive,         severity: CRITICAL }
    - { match: exe,  value: dropbox,          severity: CRITICAL }
    - { match: exe,  value: telegram-desktop, severity: WARNING }   # comm seria "telegram-deskto"
    - { match: comm, value: Discord,          severity: WARNING }
  kill_on_panic:
    - { match: exe, value: firefox }
    - { match: exe, value: chromium }
    - { match: exe, value: chrome }
    - { match: cgroup, value: "app-*torbrowser*.scope" }

browsers:
  persona_profiles:
    - ~/.mozilla/firefox/xxxx.falcao

overrides:
  NET-009: { severity: WARNING, actions: [alert_tray] }
  HOST-002: { severity: CRITICAL }
overrides_allow_downgrade: false

storage:
  dir: /media/op/vault/lethe
  log_recipients: []             # chaves públicas age da instituição; vazio = log_identity da baseline
  sensitive_recipients: []       # quem pode ler os campos sensíveis; vazio = os mesmos de log_recipients
  journald: minimal              # minimal | none

ui:
  language: pt-BR                # pt-BR | en-US
  fullscreen_alerts: true
  sound: true
  sound_repeat: 10s
```

### 13.3 Defaults sem perfil

`lethe run` sem `-p`: `egress.type: auto`, `guard.mode: off`, checks ativos desligados, todos os passivos ligados, `storage.dir` = `./lethe-data` (com aviso). Serve para uma primeira inspeção. **O modo recomendado para operar é sempre com perfil.**

---

## 14. Log, relatório e cadeia de custódia

### 14.1 Evento

JSON canônico (**RFC 8785, JCS**), um por registro:

```json
{
  "v": 1,
  "seq": 1042,
  "ts": "2026-11-15T14:03:22.418213Z",
  "mono_ns": 81234567890123,
  "session": "5f0c9e2a-7b1d-4c3e-9a8f-2d6b1e0c4a77",
  "type": "check.alert",
  "check": "DNS-001",
  "severity": "CRITICAL",
  "source": "daemon",
  "data": {
    "iface": "wlp2s0", "proto": "udp", "dst": "198.51.100.53", "dport": 53,
    "qname": { "enc": "s1", "ct": "base64…" },
    "proc": { "pid": 4121, "exe": "/usr/lib/firefox/firefox", "uid": 1000, "confidence": "high" }
  },
  "alert_id": "A-0007",
  "actions": ["block_all", "kill_processes", "alert_fullscreen"],
  "prev": "sha256:9b1f…",
  "hash": "sha256:4c7a…"
}
```

**Tipos de evento (lista fechada; um tipo novo exige mudança na spec):** `session.start`, `session.end`, `session.checkpoint`, `state.changed`, `discovery.changed`, `discovery.endpoint_changed`, `discovery.endpoint_learned`, `discovery.endpoint_unknown`, `discovery.endpoint_confirmed`, `preflight.result`, `preflight.manual_item`, `check.alert`, `check.resolved`, `alert.ack`, `response.executed`, `guard.applied`, `guard.removed`, `guard.bypass_detected`, `panic.engaged`, `panic.released`, `selftest.result`, `operator.force`, `sensor.down`, `sensor.up`, `clock.jump`, `ipc.denied`.

O schema dos eventos fica em `internal/contracts/event.schema.json` e é a fonte única: os tipos Go são gerados ou validados a partir dele.

### 14.2 Integridade

- **Encadeamento:** `hash = SHA-256(prev_hash || JCS(evento sem "hash"))`. O primeiro evento usa `prev = sha256:000…0`.
- **Chave de sessão:** no `arm`, gera-se um par Ed25519. A chave pública vai no `session.start`.
- **Checkpoints:** a cada 60 s e em cada fechamento de segmento, um `session.checkpoint` assina `(seq, hash)` com a chave de sessão. Um crash preserva assinaturas até o último checkpoint. *(A v0.1 só assinava no fim, então um crash deixava a sessão inteira sem assinatura.)*
- **Âncora externa (obrigatória para valor probatório):** uma chave gerada pela própria ferramenta só prova consistência interna; quem tem o log pode reescrever tudo com outra chave. Por isso, no `arm`, a impressão digital da chave pública (128 bits de SHA-256 da chave, em 8 grupos de 4 hex: `3df8-a7a1-…`) é mostrada para o operador registrar **fora da máquina** (ticket, caderno da operação). Se houver `storage.log_recipients` institucional, a chave pública também é cifrada para ele num arquivo `session.pub.age`.
- `lethe verify <sessão> [--expect-fingerprint FP]` valida a cadeia, os checkpoints e a assinatura final, e compara com a âncora.
- Selagem com integridade para frente (a chave evolui a cada checkpoint e a anterior é apagada, como no Forward Secure Sealing do journald): §27, v1.1.

### 14.3 Armazenamento

*(A v0.1 previa um arquivo age por segmento. O age só grava um bloco de 64 KiB quando ele enche ou quando o arquivo é fechado, então um crash perderia o segmento corrente inteiro. A v0.2 troca isso por registros selados um a um.)*

- Diretório: `storage.dir/sessions/<session-id>/`.
- `segment-000001.lseg`:
  - **cabeçalho** (1 linha JSON): versão, sessão, número do segmento, `key_wrap` (chave de dados de 32 bytes cifrada com age para `log_recipients`) e `sensitive_key_wrap` (segunda chave, cifrada para `sensitive_recipients`);
  - **registros**: `u32 len ‖ nonce(24) ‖ XChaCha20-Poly1305(evento_jcs, AD = session ‖ segment ‖ seq)`.
- Rotação: a cada 5 min ou 10 000 eventos.
- `fsync` imediato depois de todo evento CRITICAL, `alert.ack`, `response.executed` e `session.*`; nos demais, a cada 1 s. Um crash perde no máximo 1 s de eventos não críticos.
- O leitor tolera registro final truncado (crash) e o reporta como `truncated_tail`, sem quebrar a verificação do resto.
- **Trailer de segmento:** todo segmento fechado (rotação ou `disarm`) termina com `"LETHEEND" ‖ u64 contagem ‖ nonce ‖ tag`, autenticado com a chave de dados e com o hash do cabeçalho. Assim, um segmento fechado nunca pode se passar por truncado por crash: qualquer byte alterado em qualquer ponto de um segmento fechado é erro de integridade (AC-10). O cabeçalho entra nos dados associados de todo registro (SHA-256 da linha), então alterar o cabeçalho também invalida o segmento.
- **Limite inerente:** numa sessão que **não** terminou (crash), quem tem acesso ao disco pode remover registros do fim do último segmento. Isso é indistinguível de um crash e aparece como "sessão não encerrada" e "eventos após a última assinatura". Os checkpoints a cada 60 s limitam o que pode ser removido sem deixar rastro na âncora.
- Campos sensíveis (`qname`, títulos de janela, SSIDs observados) são cifrados com a **chave sensível** (`"enc": "s1"`). Quem tem só a chave de log vê os eventos, mas não esses campos.
- Fora de `storage.dir`: nada vai para `/var/log`. No journald, `minimal` registra uma linha de início e uma de fim, sem dados; `none` não registra nada.

### 14.4 Timestamps

UTC com microssegundos mais `CLOCK_MONOTONIC`. Saltos de relógio são registrados (SELF-005). O relógio de parede **não** prova ordem; quem prova é `seq` mais a cadeia.

### 14.5 Relatório

`lethe report <sessão> --format md|json [--include-sensitive]`:

- Identificação: operação, persona, pseudônimo do operador, hash SHA-256 do perfil e da baseline (nunca o conteúdo).
- Duração, linha do tempo por cor e porcentagem do tempo em VERDE.
- Todos os alertas, com contador, reconhecimento, motivo e marca de "não reconhecido".
- Respostas executadas, com latência medida.
- Preflight (incluindo as respostas do checklist manual e o uso de `--force`) e o último selftest.
- Hash final, checkpoints, assinatura, chave pública e impressão digital da sessão.

---

## 15. CLI

### 15.1 Comandos

| Comando | Descrição |
|---|---|
| `lethe baseline create [--manual] [--allow-tunnel] [--out FILE] [--recipient AGE]` | Cria a baseline cifrada |
| `lethe baseline add-network [--manual] FILE` | Adiciona uma rede conhecida |
| `lethe baseline show FILE` | Mostra o conteúdo (pede a passphrase) |
| `lethe setup` | Assistente do primeiro uso: perfil + baseline, começando em `off` (§10.6) |
| `lethe profile init [--out FILE]` | Gera um perfil comentado (guarda `off`) |
| `lethe profile validate FILE` | Valida contra o schema |
| `lethe discover [--json] [--learn]` | Mostra o que foi descoberto (sem armar) |
| `lethe preflight -p FILE [--json] [--no-manual]` | Roda o preflight |
| `lethe run -p FILE [--guard off\|reactive\|strict] [--no-gui] [--tui] [--no-active] [--force --reason TEXT]` | Modo portátil: sobe o daemon em primeiro plano e arma |
| `lethe arm -p FILE [--force --reason TEXT]` / `lethe disarm` | Com o daemon rodando como serviço |
| `lethe status [--json]` | Estado, alertas abertos, sensores e, se houver, o bloqueio ativo com a saída (`lockdown`). Sem daemon, procura tabelas `lethe*` que sobraram (§10.6) |
| `lethe events [--follow] [--severity S] [--json]` | Fluxo de eventos |
| `lethe ack ID --reason TEXT` | Reconhece um alerta |
| `lethe panic` / `lethe unpanic` | Bloqueio manual / liberação |
| `lethe selftest [--case ID] [--json] [--yes]` | Autoteste (§18), dentro da sessão armada; `--yes` confirma o RESP-001 sem perguntar |
| `lethe report SESSÃO [--format md\|json] (--identity FILE \| --baseline FILE)` | Relatório |
| `lethe verify SESSÃO [--expect-fingerprint FP] (--identity FILE \| --baseline FILE)` | Verificação de integridade |
| `lethe cleanup` | Remove tabelas `lethe*`, socket e arquivos temporários e diz o que removeu |
| `lethe version [--json]` | Versão, commit, hash do binário, data da base geo |
| `lethe daemon` / `lethe agent` | Internos (o `run` e as unidades systemd os chamam) |

Toda saída com `--json` segue schemas em `internal/contracts/`. A saída humana vai em pt-BR ou en-US conforme `ui.language` ou `LANG`.

### 15.2 Códigos de saída

| Código | Significado |
|---|---|
| 0 | Sucesso |
| 1 | Erro genérico |
| 2 | Preflight com falha crítica |
| 3 | A sessão terminou com pelo menos um CRITICAL |
| 4 | A verificação de integridade falhou |
| 5 | Autenticação falhou (passphrase incorreta ou peer não autorizado) |
| 6 | Arm desfeito: o túnel não provou tráfego com o guarda dentro de `guard.arm_confirm` (§10.6) |
| 10 | Privilégios insuficientes |
| 11 | Requisito de sistema ausente (kernel, nftables, cgroup v2) |
| 12 | Daemon inacessível |

---

## 16. GUI e TUI

### 16.1 Bandeja

Ícone com a cor do estado e um contador de alertas abertos. Menu: abrir painel, pânico, selftest, desarmar.

### 16.2 Painel

- **Cabeçalho:** operação e persona, tempo de sessão, modo do guarda, IP e país de saída (último check ativo), túnel identificado.
- **Grade de checks:** um cartão por categoria; cada check com estado, última avaliação e detalhe.
- **Linha do tempo:** eventos filtráveis por severidade e por check.
- **Botões:** Pânico (sempre visível, vermelho), Selftest, Reconhecer, Desarmar.

### 16.3 Alerta em tela cheia

- Fundo vermelho, título do check, uma frase dizendo o que significa, destino e processo envolvidos, ações já executadas ("Rede bloqueada. Navegadores encerrados.") e o que fazer agora.
- Não fecha com Esc nem com clique fora. Só fecha com "Reconhecer", motivo e passphrase.
- Som repetido a cada `ui.sound_repeat` até o reconhecimento.

### 16.4 Ressalvas de Wayland e da toolkit

- A Fyne expõe `RequestAlwaysOnTop()`, mas é um pedido: o compositor pode ignorar. No Wayland, GNOME não honra "acima de tudo" para janelas comuns. KDE honra pelo KWin.
- Mitigação obrigatória: **sempre** mandar também uma notificação com urgência crítica (`urgency=2`) e tocar o som, pelo agente. A GUI tenta a tela cheia e registra se conseguiu foco (`alert.fullscreen_result`, dentro de `response.executed`).

### 16.5 TUI

Mesmas informações (estado, grade, eventos), com os atalhos `p` (pânico), `a` (reconhecer), `s` (selftest), `q` (sair sem desarmar). No `run --tui` sem GUI, a TUI é a superfície de alerta: tela vermelha inteira e sino do terminal.

### 16.6 Idioma

pt-BR por padrão; en-US disponível. Todo texto de alerta tem uma versão curta (título) e uma longa (o que fazer), em `internal/i18n/*.toml`, com teste que falha se alguma chave faltar em algum idioma.

---

## 17. IPC

### 17.1 Transporte

- Unix domain socket em `/run/lethe/lethe.sock` (serviço) ou `$XDG_RUNTIME_DIR/lethe/lethe.sock` do `SUDO_UID` (portátil). Diretório `0700`, socket `0600`, dono = operador.
- Autenticação do peer: `SO_PEERCRED`. Só o UID do operador e o root são aceitos. Os demais geram `ipc.denied` e têm a conexão fechada.
- Não existe nenhuma porta TCP.

### 17.2 Protocolo

JSON-RPC 2.0, uma mensagem por linha, máximo de 64 KiB por mensagem (acima disso, a conexão é fechada). Schemas em `internal/contracts/ipc/`.

| Método | Classe |
|---|---|
| `status.get`, `events.subscribe`, `events.query`, `discovery.get`, `heartbeat` | leitura |
| `panic.engage`, `selftest.run` (sem RESP-001), `agent.report` (só para o agente) | controle seguro |
| `session.arm`, `session.disarm`, `alert.ack` (CRITICAL), `panic.release`, `discovery.confirm_endpoint`, `selftest.run` com RESP-001 | **sensível** |
| `alert.ack` (WARNING/INFO) | controle seguro |
| `gui.fullscreen_result` (a GUI informa se o alerta em tela cheia apareceu: `focused`, `shown` ou `failed`; vira `response.executed` do `alert_fullscreen`, uma vez por alerta) | controle seguro |

### 17.3 Ações sensíveis

O navegador comprometido roda com o UID do operador e, portanto, passaria no `SO_PEERCRED`. Por isso, métodos **sensíveis** exigem uma prova de conhecimento da passphrase da baseline:

1. O cliente pede `auth.challenge` e recebe um nonce de 32 bytes (validade de 30 s, uso único).
2. O cliente manda `HMAC-SHA256(K, nonce ‖ método ‖ params_jcs)`, onde `K = scrypt(passphrase, salt_sessão)`. O salt vai no `session.start`.
3. O daemon confere com a `K` que mantém em memória protegida. Erros geram `ipc.denied`; depois de 5 erros em 5 min, abre-se SELF-006 CRITICAL e, com guarda `strict` ou `reactive`, o daemon entra em pânico. Com guarda `off`, as ações sensíveis ficam travadas por 5 min, sem bloqueio de rede (§10.6).

Assim, a passphrase não trafega pelo socket. (Um keylogger no X11 continua sendo um risco: §22.)

---

## 18. Autoteste (selftest)

### 18.1 Princípio

O autoteste **não pode gerar um vazamento real**. Todo tráfego de teste usa destinos de documentação, que não são roteados na internet:

- IPv4: RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
- IPv6: `2001:db8::/32` (RFC 3849)

Esses pacotes chegam, no máximo, ao roteador do operador. Eventos de autoteste levam `selftest: true` e não disparam respostas reais: o motor de respostas roda em **dry-run**, exceto no RESP-001.

**No modo estrito**, para os casos que precisam ver o pacote no sensor (ST-NET-001 etc.), o daemon insere temporariamente uma regra `accept` com a 5-tupla exata do teste (porta de origem efêmera escolhida pelo teste, destino de documentação e `meta skuid 0`), executa o caso e a remove na mesma rodada. Cada caso roda nos dois sentidos quando faz sentido: "o sensor vê" (com a exceção) e "o guarda bloqueia" (sem ela).

### 18.2 Casos

| Caso | Valida | Como |
|---|---|---|
| ST-NET-001 | NET-001 | UDP para `192.0.2.1:9` com `SO_BINDTODEVICE` na interface egress |
| ST-NET-002 | NET-002 (estrito) | O mesmo, sem a exceção: deve aparecer como tentativa bloqueada, com UID |
| ST-NET-003 | NET-003/NET-001 v6 | UDP para `[2001:db8::1]:9` pela interface egress (se houver v6; sem IPv6 global no egress, SKIP) |
| ST-NET-006 | NET-006 | Cria e remove uma interface `dummy` temporária (`lethe-st0`) |
| ST-NET-010 | NET-010 | TCP SYN para `198.51.100.1:443` pela egress; o evento precisa vir atribuído ao PID do selftest com `confidence: high` |
| ST-NET-012 | NET-012 | UDP com cabeçalho STUN Binding Request para `203.0.113.1:3478` |
| ST-DNS-001 | DNS-001 | Consulta DNS com nome aleatório para `192.0.2.53:53` pela egress; o qname cifrado precisa decifrar para o mesmo valor |
| ST-DNS-004 | DNS-004 | Altera e restaura um arquivo de teste sob vigilância (não o resolv.conf real) |
| ST-TUN-004 | TUN-004 | Cria e remove a tabela `inet lethe_selftest` |
| ST-HOST-001 | HOST-001 | Re-executa `/proc/self/exe` como `lethe-st-deny` (nome da lista de negação do teste) e encerra o processo |
| ST-SELF-001 | SELF-001 | Pausa um sensor por 4 s; o estado precisa ir para CINZA e voltar |
| ST-SELF-002 | SELF-002 | Força o descarte (buffer de recepção mínimo + rajada de 2000 pacotes de teste) e espera `tp_drops > 0` |
| RESP-001 | `block_all` | Aplica e remove o pânico de verdade, mede a latência e confirma que o tráfego de teste foi bloqueado. Ação sensível: derruba a conexão por cerca de 1 s |

### 18.3 Resultado

Tabela pass/fail com a latência de detecção por caso, gravada no log e em `storage.dir/state/selftest.json` (lido pelo SELF-004; só uma rodada completa atualiza o arquivo). O selftest roda no daemon da sessão armada (`selftest.run`); os achados que ele causa são reconhecidos pelo fluxo exato, pela interface, tabela, PID ou arquivo do caso e gravados com `selftest: true` e o plano de respostas em dry-run (ADR 0010). Qualquer falha deixa o preflight em WARNING; uma falha em ST-NET-001, ST-NET-002 (no estrito) ou RESP-001 o deixa em CRITICAL.

---

## 19. Segurança da própria ferramenta

### 19.1 Sem comunicação própria

- Nenhuma telemetria, verificação de update, download de base ou relatório de crash.
- As únicas conexões de rede são os checks ativos habilitados (sempre pelo túnel) e o `baseline create` online.
- **Teste no CI:** a suíte e2e roda em network namespaces sem rota para fora; um sniffer na "internet simulada" falha o teste se aparecer qualquer pacote que não tenha sido gerado pelo próprio teste (AC-12).

### 19.2 Build e distribuição

- Builds reprodutíveis: `CGO_ENABLED=0` para `lethe` (binário estático), `-trimpath`, `-buildvcs=true`, toolchain fixada em `.mise.toml`, `SOURCE_DATE_EPOCH`. O `lethe-gui` usa cgo (OpenGL), num módulo Go separado.
- Binários e pacotes assinados (minisign ou Sigstore/cosign; o dono do projeto assina, o agente não tem a chave). `lethe version` mostra o SHA-256 do próprio binário.
- SBOM CycloneDX por release (`cyclonedx-gomod`).
- Distribuição por repositório interno da instituição, nunca por download público na hora da operação.

### 19.3 Privilégios

Depois de inicializar como root (abrir sockets, ler a baseline, fazer fork do agente), o daemon:

1. mantém uid 0, mas reduz os conjuntos de capabilities (efetivo, permitido, herdável e bounding) para:

| Capability | Uso |
|---|---|
| `CAP_NET_RAW` | AF_PACKET, `SO_BINDTODEVICE` |
| `CAP_NET_ADMIN` | nftables, netlink, link down, NFLOG, `dummy` do selftest |
| `CAP_KILL` | Respostas |
| `CAP_SYS_PTRACE` | Ler `/proc/<pid>/fd` e `environ` de outros UIDs (atribuição) |
| `CAP_DAC_READ_SEARCH` | Ler cookie do Tor, perfis de navegador, configs |
| `CAP_IPC_LOCK` | `mlock` além do `RLIMIT_MEMLOCK` |

2. aplica `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE=0` e `RLIMIT_CORE=0`;
3. aplica seccomp em duas fases. **Fase 1 (já no M8):** uma denylist, em todas as threads (`SECCOMP_FILTER_FLAG_TSYNC`), das syscalls que o daemon nunca usa e que servem para escalar ou sair do confinamento (`open_by_handle_at`, módulos de kernel, `kexec_*`, `mount`, `pivot_root`, `chroot`, `setns`, `unshare`, `ptrace`, `process_vm_writev`, `bpf`, `perf_event_open`, `keyctl`, `userfaultfd`, `reboot`, `swapon`/`swapoff`, ajuste de relógio, entre outras), respondendo `EPERM`; ela nunca mata o processo, então não derruba uma sessão por causa de uma syscall esquecida. **Fase 2 (M14):** primeiro em modo `SECCOMP_RET_LOG` para levantar as syscalls na suíte e2e, depois em allowlist (`SECCOMP_RET_KILL_PROCESS`).

**Em Go, as capabilities são por thread do sistema.** O descarte DEVE usar `kernel.org/pub/linux/libs/security/libcap/cap` (aplica em todas as threads via `psx`), nunca `syscall` direto.

No modo serviço, a unidade tem: `CapabilityBoundingSet=` (a lista acima), `AmbientCapabilities=` (vazio), `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths=` (com o `storage.dir`, que DEVE ser declarado num drop-in, senão `ProtectSystem` o deixa só leitura), `ProtectHome=read-only`, `PrivateTmp=yes`, `MemoryDenyWriteExecute=yes`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_PACKET AF_INET AF_INET6`, `LockPersonality=yes`, `RestrictNamespaces=yes`.

### 19.4 Memória

- Baseline decifrada, chave de sessão, `K` (§17.3) e chaves de dados ficam em buffers com `mlock` e são zerados ao sair (`memguard` ou buffers próprios com `unix.Mlock` + zeragem explícita; nunca `string` em Go para segredos).
- Core dumps desabilitados (§19.3).

### 19.5 Superfície de ataque

- O parser de pacotes só decodifica o necessário (Ethernet/VLAN, IPv4/IPv6, UDP/TCP, DNS, cabeçalho STUN, mDNS/LLMNR/NetBIOS) e tem fuzzing (`go test -fuzz`) no CI com corpus versionado.
- Também têm fuzzing: o leitor de segmentos do log, o decodificador JSON-RPC, o parser de perfil e o cliente de controle do Tor.
- O perfil é validado por schema antes de qualquer uso, e os caminhos são canonizados.
- Nenhum `exec` de comando externo (princípio 10). Um teste estático (`depguard` mais um grep no CI) proíbe `os/exec` fora de `internal/privsep`.

---

## 20. Stack técnica e repositório

### 20.1 Bibliotecas

| Área | Escolha | Observação |
|---|---|---|
| Linguagem | Go (última estável; 1.27 em nov/2026) | Fixada em `.mise.toml` |
| Captura | `github.com/mdlayher/packet` (pure Go; mantido no fork `antrea.io/packet`, que deve ser o preferido) + `golang.org/x/net/bpf` | **Troca em relação à v0.1:** o `afpacket` do gopacket usa cgo |
| Decodificação | `github.com/gopacket/gopacket/layers` (pure Go) | Só decodificação |
| Netlink | `github.com/vishvananda/netlink` | Links, endereços, rotas, regras, subscriptions, `SocketDiag*` (sock_diag) |
| nftables | `github.com/google/nftables` | Pure Go, transações, sets, `expr.Log`, `expr.Socket` (cgroupv2) e monitor |
| NFLOG | `github.com/florianl/go-nflog/v2` | NET-002 com UID/GID |
| WireGuard | `golang.zx2c4.com/wireguard/wgctrl` | — |
| Tor | cliente de controle próprio (`internal/discovery/torctl`) | O `cretz/bine` é grande demais para o uso |
| DNS | `github.com/miekg/dns` | Decodificação, resolvedor preso ao túnel |
| D-Bus | `github.com/godbus/dbus/v5` | resolved, NM, timedated, locale1, login1, GeoClue; notificações (agente) |
| /proc | `github.com/prometheus/procfs` | Processos, cgroups, fds |
| inotify | `github.com/fsnotify/fsnotify` | — |
| Geo/ASN | `github.com/oschwald/maxminddb-golang/v2` + DB-IP Lite Country e ASN (CC BY 4.0; atribuição em `docs/THIRD_PARTY.md`) | Embutido via `embed`; `scripts/update-geo` com URL e SHA-256 fixados (quem roda é o dono) |
| Cifra | `filippo.io/age` + `golang.org/x/crypto/chacha20poly1305` | Baseline, envelope das chaves, registros |
| JSON canônico | `github.com/gowebpki/jcs` (ou implementação própria testada contra os vetores da RFC 8785) | — |
| Assinatura | `crypto/ed25519` | — |
| Capabilities | `kernel.org/pub/linux/libs/security/libcap/cap` | Todas as threads |
| Seccomp | `github.com/elastic/go-seccomp-bpf` | Pure Go |
| CLI | `github.com/spf13/cobra` | — |
| YAML e schema | `github.com/goccy/go-yaml` + `github.com/santhosh-tekuri/jsonschema/v6` | — |
| TUI | `github.com/charmbracelet/bubbletea` | — |
| GUI | Fyne (`fyne.io/fyne/v2`) | Decisão D2 (§25) |
| Bandeja | `fyne.io/systray` | StatusNotifierItem |
| Pacotes | `nfpm` | deb e rpm |

Antes de adicionar uma dependência fora desta tabela, o agente DEVE justificá-la num ADR (o que ela faz que a stdlib e as já listadas não fazem, tamanho, saúde de manutenção).

### 20.2 Repositório

Segue o padrão de monorepo do dono (contrato + perfil Go). São dois módulos Go num `go.work`: o núcleo, sem cgo, e a GUI, com cgo.

```
lethe/
├── AGENTS.md                 # guia do agente (mapa, comandos, regras, done)
├── CLAUDE.md                 # @AGENTS.md
├── README.md
├── spec.md                   # esta especificação (fonte da verdade do escopo)
├── .mise.toml                # toolchain + tasks (check, check:all, fix, test, e2e, fuzz, gen)
├── go.work
├── go.mod                    # módulo núcleo (CGO_ENABLED=0)
├── apps/
│   ├── lethe/                # main: cobra; subcomandos daemon, agent, run…
│   └── lethe-gui/            # módulo separado (go.mod próprio, cgo), só fala IPC
├── internal/
│   ├── contracts/            # JSON Schemas: event, ipc, profile, outputs --json; tipos Go
│   ├── engine/               # PURO: severidade, dedup, alertas, cor, máquina da sessão
│   ├── checks/               # um arquivo por check (net001.go…) + registry (ADR 0004)
│   ├── discovery/            # interfaces, classificação, túnel, DNS, torctl/
│   ├── sensors/              # capture/, nflog/, netlinkmon/, sockdiag/, procscan/, nftmon/, dbusmon/
│   ├── guard/                # geração e aplicação das tabelas nftables
│   ├── response/             # ações
│   ├── journal/              # JCS, cadeia, segmentos, checkpoints, verify
│   ├── baseline/
│   ├── profile/
│   ├── report/
│   ├── ipc/                  # servidor/cliente JSON-RPC, auth challenge
│   ├── agent/                # lado de sessão (D-Bus de sessão, PipeWire, notificações)
│   ├── selftest/
│   ├── privsep/              # fork/exec de /proc/self/exe, caps, seccomp (único lugar com os/exec)
│   ├── geo/                  # mmdb embutido
│   ├── i18n/
│   └── platform/             # detecção de kernel, features e distro
├── assets/                   # ícones, sons, mmdb, schema
├── packaging/                # nfpm.yaml, unidades systemd
├── test/
│   ├── e2e/                  # cenários em network namespaces (tag de build `e2e`)
│   └── netlab/               # helper que monta a topologia de teste (§23.2)
├── scripts/                  # update-geo, release (documentados, idempotentes)
└── docs/
    ├── adr/                  # NNNN-titulo.md
    ├── runbooks/             # operação, recuperação após crash, verificação de sessão
    ├── archive/spec-v0.1.md
    └── THIRD_PARTY.md
```

*(A v0.1 usava `cmd/`. A v0.2 usa `apps/`, conforme o padrão do dono; decisão D9 em §25.)*

Fronteiras (impostas pelo `depguard` no `check`):

- `internal/engine` não importa `net`, `os`, `syscall`, `time.Now` (recebe `Clock`) nem nenhum outro pacote `internal/` além de `contracts`.
- `internal/checks` não importa `response` nem `guard`.
- `os/exec` só pode aparecer em `internal/privsep`.
- `apps/lethe-gui` só importa `internal/contracts`, `internal/ipc` (cliente) e `internal/i18n` (os textos de operador; dados embutidos, sem I/O). Os tipos das respostas IPC (`Status`, `SelftestResult`…) ficam em `internal/contracts`. Um teste do módulo da GUI impõe essa fronteira.

---

## 21. Requisitos não funcionais

| Requisito | Meta | Como é medido |
|---|---|---|
| Latência de detecção (NET-001, DNS-001, NET-003) | ≤ 1 s (alvo ≤ 200 ms) | e2e: do `sendto` ao evento no IPC |
| Latência de `block_all` após a detecção | ≤ 200 ms | `response.executed.latency_ms` |
| Latência até o alerta em tela cheia | ≤ 500 ms | GUI registra o tempo até mostrar a janela |
| Tempo do `run` até ARMADO | ≤ 10 s (sem contar a passphrase) | e2e |
| CPU do daemon (repouso / 100 Mbit/s no túnel) | < 1 % / < 3 % de um núcleo | benchmark e2e com iperf3 entre namespaces |
| Memória do daemon | < 150 MB RSS | idem |
| Tamanho do binário `lethe` | < 40 MB (com mmdb) | CI |
| Perda na captura | 0 a até 1 Gbit/s de tráfego **permitido** na interface egress | benchmark e2e: o filtro descarta o permitido no kernel |
| Conexões próprias de rede | zero, fora dos checks ativos habilitados | AC-12 |
| Resíduos após `disarm` ou `cleanup` | zero tabelas `lethe*`; zero arquivos fora de `storage.dir` e `$RUNTIME_DIR/lethe` | AC-13 |
| Cobertura de testes | ≥ 85 % em `engine`, `journal`, `contracts`, `profile`; ≥ 70 % no resto | `go test -cover` no `check:all` |

---

## 22. Limitações conhecidas

1. **Host comprometido com root** pode cegar o daemon, alterar a captura ou matar o processo. No modo estrito, a tabela permanece (fail-closed), mas nada é garantido contra root local. Mitigações futuras: modo de isolamento por namespace e modo sensor externo (§27).
2. **O modo reativo vaza o primeiro pacote.** Por isso, o recomendado é o estrito.
3. **A atribuição de processo por sock_diag e /proc é melhor esforço:** conexões UDP curtas podem terminar antes da consulta. O evento é registrado mesmo assim, com `confidence: none`. Atribuição exata via eBPF fica para a v1.1.
4. **Vazamentos dentro do túnel não são vazamentos de IP:** um documento-beacon aberto passa pelo túnel e revela o IP da VPN, não o real, mas revela atividade e horário. Recomendação (checklist): abrir arquivos de alvos só em VM offline. Os candidatos WebRTC com IP de LAN enviados **dentro** do túnel (SDP) também não são vistos; o PER-002 verifica a configuração que os evita.
5. **Fingerprint do navegador** não é avaliado na v1.
6. **Wayland:** o alerta em tela cheia pode não tomar o foco (§16.4).
7. **A base geográfica offline envelhece.** Ela é atualizada a cada release, e a data aparece no `version` e no relatório.
8. **Reboot remove o guarda.** É intencional e exige novo `arm`.
9. **iptables-legacy** não é inspecionado (TUN-007 só avisa).
10. **`PACKET_QDISC_BYPASS`:** frames enviados por sockets AF_PACKET com essa opção não passam pelos taps. A camada `netdev egress` (≥ 5.16) os bloqueia no estrito, mas o sensor não os vê.
11. **Tor só dentro de VM (Whonix-Gateway) sem VPN no host**, e transportes `snowflake`/`meek`, não funcionam no modo estrito (TUN-008).
12. **Keylogger no X11:** qualquer processo do mesmo UID lê o teclado no X11, inclusive a passphrase digitada na GUI. No X11, a passphrase DEVERIA ser digitada no terminal do `run` (pinentry no TTY). No Wayland, isso não se aplica.
13. **Túnel ocioso no arm estrito:** sem tráfego e sem keepalive, um WireGuard pode ficar mais de 180 s sem handshake. A janela de confirmação (§10.6) então desfaz o arm; basta abrir uma página durante a janela ou configurar `PersistentKeepalive`.
14. **Containers em outros network namespaces:** os sockets deles não são atribuídos (o sock_diag só vê o namespace do daemon), mas o tráfego deles que sai pela egress é visto e bloqueado normalmente.
15. **Layout de teclado no GNOME:** o GNOME guarda o layout da sessão no dconf, que o agente não lê; o PER-001 usa então o layout do sistema (`org.freedesktop.locale1`). O compartilhamento de tela (HOST-003) é reconhecido pelos nós `Video/Source` do PipeWire com nome de compositor (gnome-shell, mutter, kwin, xdpw, obs): um compositor com outro nome passa despercebido (ADR 0009).

---

# Parte II — Execução

## 23. Estratégia de testes

### 23.1 Camadas

| Camada | O que cobre | Onde | Precisa de root? |
|---|---|---|---|
| Unit | engine, journal, profile, baseline, classificação, gerador de BPF e de regras nft (testado como **dados**: a lista de expressões gerada), parsers | colocados ao lado do código, `*_test.go` | não |
| Golden | saída de `report`, `status --json`, `profile init`, ruleset gerado | `testdata/*.golden`, atualizado com `-update` | não |
| Fuzz | parsers (§19.5) | `Fuzz*` + `testdata/fuzz` | não |
| Integração | sensores reais (AF_PACKET, netlink, nftables, NFLOG, sock_diag) num namespace descartável | `test/e2e`, tag `e2e` | **sim** (root, ou userns quando o kernel permite) |
| E2E | cenários completos AC-01…AC-13 | `test/e2e` | sim |
| Manual | Wi-Fi, NM, Tor Browser real, GUI no GNOME/KDE | `docs/runbooks/manual-acceptance.md` | sim |

### 23.2 Laboratório de rede (`test/netlab`)

Helper em Go que monta, para cada teste, esta topologia com nomes aleatórios:

```
 ns "dut" (onde roda o lethe)            ns "isp" (roteador)                ns "vpn" (servidor WG)
 ┌────────────────────────┐   veth   ┌──────────────────────────┐  veth  ┌─────────────────────┐
 │ eth0 (egress, override)│──────────│ isp0  10.0.0.1            │────────│ wg-srv 198.18.0.2   │
 │ wg0  (tunnel)          │          │ sniffer (AF_PACKET) em isp0│        │ wg0 (servidor)      │
 └────────────────────────┘          │ "internet": 192.0.2.0/24,  │        └─────────────────────┘
                                     │ 2001:db8::/32 → blackhole  │
                                     └──────────────────────────┘
```

- `eth0` é veth, então não tem `/sys/class/net/*/device`. O teste usa `network.egress_ifaces: [eth0]` (override da §7.2).
- O sniffer em `isp0` é a **captura externa** que prova que nada vazou (AC-04, AC-09, AC-12).
- WireGuard: módulo do kernel, se disponível; senão, `wireguard-go` em userspace. Se nenhum dos dois existir, os testes que dependem dele são marcados como `SKIP` com o motivo.
- **Trava de segurança:** antes de qualquer operação, o netlab compara o inode de `/proc/self/ns/net` com o de `/proc/1/ns/net` e **aborta** se for o namespace do host. Nenhum teste aplica nftables no namespace do host.
- Comando: `mise run e2e`. Ele tenta `unshare --user --map-root-user --net` e, se o kernel ou o AppArmor (Ubuntu 24.04+) bloquearem, pede `sudo -E` explicitamente. No CI (GitHub Actions `ubuntu-latest`), roda com `sudo`.

### 23.3 Matriz de rastreabilidade

Todo check tem pelo menos um teste unit e, quando há sensor envolvido, um teste e2e. O nome do teste começa pelo ID: `TestNET001_LeakDetected`, `TestE2E_AC04_TunnelDown`. O script `scripts/trace-matrix` (rodado no `check:all`) falha se um ID da §9 não tiver teste com o seu nome.

---

## 24. Plano de implementação (marcos)

Regras para o agente:

- Execute os marcos **em ordem**. Cada um termina com `mise run check` verde e, se tiver testes e2e, `mise run e2e` verde (ou `SKIP` justificado).
- Um marco = um ou mais commits Conventional Commits, atômicos, que passam no `check`. Escopo do commit = pacote (`feat(journal): …`).
- Não implemente nada de um marco posterior "porque é fácil". Stubs são permitidos se retornarem erro `ErrNotImplemented` e tiverem teste.
- Ao fim de cada marco, atualize a seção "Estado" do `AGENTS.md` (marco atual, o que ficou pendente).
- **Nunca** rode `lethe run`/`arm` com guarda `strict` ou `reactive`, nem `panic`, no namespace do host da máquina de desenvolvimento: isso derruba a rede. Use o netlab.

| Marco | Entrega | Pronto quando |
|---|---|---|
| **M0 — Esqueleto** | `go.work`, `go.mod`, `.mise.toml` (tasks `check`, `check:all`, `fix`, `test`, `e2e`, `fuzz`, `gen`), `.golangci.yml` com as fronteiras da §20.2, lefthook, CI, `AGENTS.md`, `CLAUDE.md`, ADRs 0001 (stack) e 0002 (distribuição), `lethe version` | `mise run check` verde num clone limpo; `lethe version --json` passa no schema |
| **M1 — Contratos e engine** | `internal/contracts` (event, ipc, profile, outputs), `internal/engine` (severidade, dedup, ciclo de vida do alerta, cor, precedência, máquina de sessão, plano de respostas por guarda) | Testes por tabela de todas as transições da §6.1 e de todas as regras da §10; cobertura ≥ 85 %; sem I/O (depguard) |
| **M2 — Journal** | JCS, cadeia, segmentos selados, rotação, fsync, checkpoints, leitor tolerante a cauda truncada, `lethe verify`, `lethe report` (md/json) a partir de um journal sintético | AC-10 em unit; fuzz do leitor por 60 s sem falha; vetores da RFC 8785 passam; golden do relatório |
| **M3 — Perfil e baseline** | Schema e validação (inclusive `comm` > 15), `profile init/validate`, baseline (age, passphrase, `--manual`, `add-network`, `show`), `log_identity` | Perfil da §13.2 valida; campo desconhecido falha; round-trip da baseline; nenhum valor da baseline aparece em nenhuma saída (teste com valores-sentinela) |
| **M4 — Descoberta** | Classificação (§7.2), WireGuard (`wgctrl`), rotas, DNS (resolv.conf + resolved via D-Bus, com fake de D-Bus nos testes), IPv6, `lethe discover --json` | e2e no netlab: `eth0` = egress, `wg0` = tunnel, endpoint do servidor descoberto; unit da classificação com fixtures de topologia (vlan, bond, bridge, unknown) |
| **M5 — Captura** | Gerador de cBPF a partir do allowlist (testado como dados + e2e), sensor AF_PACKET, classificador (§8.3), decodificação de DNS e STUN, sock_diag + atribuição (NET-010), NET-003/004/005/006 | AC-01, AC-02, AC-03 no netlab; ST-NET-001/003/010/012 e ST-DNS-001 rodando no netlab; fuzz do parser |
| **M6 — Guarda** | Tabelas `inet lethe`, `lethe_panic`, `netdev lethe_l2`, `bridge lethe` (gerador + aplicação), atualização de sets, NFLOG (NET-002), vigilância do cgroup (§11.2), `cleanup` | AC-04, AC-08 (parte nft), AC-09, AC-13 no netlab; o ruleset gerado tem golden test; o sniffer externo não vê nenhum pacote vazado |
| **M7 — Daemon, IPC e CLI** | Orquestração, servidor IPC com papéis e auth challenge (§17.3), respostas (§10.3), `run`/`arm`/`disarm`/`status`/`events`/`ack`/`panic`/`unpanic`, `privsep` (fork do agente, descarte de caps), preflight automático + manual no terminal | AC-08 completo; um peer de outro UID é recusado; ação sensível sem HMAC é recusada; 5 erros → pânico; caps efetivas conferidas em `/proc/self/status` |
| **M8 — Túneis** | OpenVPN/genérico (sock_diag do processo do cliente + aprendizado via NFLOG), `discover --learn`, `torctl` próprio, PTs (§7.5), TUN-001…008 (TUN-006 com a lógica e a interface da base geo; os dados chegam no M11), seccomp fase 1 (§19.3), agente reconhecido pelo executável e não só pelo PID, limite da lista de alertas do engine | AC-05, AC-06 no netlab; AC-07 no netlab com `tor` do sistema se existir o binário (senão SKIP + runbook manual) |
| **M8.1 — Uso seguro** | §10.6 itens 1–7 e 9: `--force` limitado, janela de confirmação do arm, SELF-006 sem bloqueio no `off`, perfil gerado em `off`, `lockdown` no `status`, `status` sem daemon, `cleanup` explicado, `report`/`verify --baseline` | AC-16, AC-17, AC-18 no netlab |
| **M9 — Host, persona, autodiagnóstico e agente** | HOST-001…009, PER-001…003, SELF-001…005, NET-007/008/009/013/014, `lethe agent` (notificações, PipeWire, portal, teclado) | Unit com fixtures de `/proc` e de D-Bus; e2e de SELF-001/002; teste de que dado do agente nunca rebaixa severidade |
| **M10 — Selftest** | Todos os casos da §18.2, exceções temporárias no estrito, dry-run das respostas, `selftest.json`, `lethe setup` (§10.6 item 8: o assistente usa o selftest para oferecer o estrito) | AC-11 no netlab; `setup` testado com entradas simuladas |
| **M11 — Checks ativos e geo** | NET-011 (VPN com bind + resolvedor no túnel; Tor via SOCKS5h), base embutida (que ativa o TUN-006 do M8), PER-001 completo | Servidor HTTP falso dentro do ns "vpn" responde o IP; nenhuma consulta sai pela egress (sniffer); cenário "resolvedor do túnel ausente" → skip com W |
| **M12 — TUI** | bubbletea; tela de alerta; atalhos | Teste com `teatest` (golden das telas) |
| **M13 — GUI** | Módulo `apps/lethe-gui`: bandeja, painel, tela cheia, entrada de passphrase | Build no CI; teste com o driver de teste da Fyne; runbook manual GNOME/KDE, X11/Wayland |
| **M14 — Endurecimento e empacotamento** | seccomp fase 2 (log → allowlist em enforce), unidades systemd, nfpm deb/rpm, build reprodutível (dois builds = mesmo hash), SBOM, `docs/runbooks/`, `docs/THIRD_PARTY.md` | AC-12; e2e completo com seccomp em enforce; `check:all` verde; dois builds com hash idêntico |
| **M15 — Entrega** | Guia de release e deploy para o dono (assinatura, repositório interno) | `docs/runbooks/release.md` completo; a automação não assina nem publica |

---

## 25. Decisões padrão (antes "questões em aberto")

Cada decisão vira um ADR em `docs/adr/` no M0 e pode ser revista pelo dono a qualquer momento. O agente não as reabre.

| # | Questão (v0.1) | Decisão padrão | Por quê |
|---|---|---|---|
| D1 | Nome definitivo | `lethe` (o diretório e o título já usavam esse nome) | Curto, sem colisão com nomes de pacotes comuns |
| D2 | GUI: Fyne ou Wails | **Fyne** | Não depende de WebKitGTK; tem `RequestAlwaysOnTop`; a GUI é opcional e fica em módulo separado |
| D3 | Chaves institucionais | Opcionais. Sem elas, os logs usam a `log_identity` da baseline. Com elas, `log_recipients` e `sensitive_recipients`, e a chave pública da sessão é cifrada para a instituição | Funciona sozinho no primeiro dia; não bloqueia a implementação |
| D4 | Política de `--force` | Uma pessoa, com `--reason` obrigatório e passphrase; vira `operator.force` no log e aparece em destaque no relatório. Regra de dois fica para a v1.1 | Simples e auditável |
| D5 | Endpoints dos checks ativos | Serviços públicos (Tor Project, Mullvad) por padrão, configuráveis; User-Agent genérico | Endpoint exclusivo da instituição viraria uma assinatura que liga personas |
| D6 | Retenção | Fora do escopo da ferramenta: ela nunca apaga sessões; a política fica no runbook | Retenção é política institucional |
| D7 | Checklist manual | Obrigatório em toda sessão (`--no-manual` só fora de `arm`/`run`) | O custo é baixo e a falha é grave |
| D8 | Tor com PTs dinâmicos | Não suportado no estrito (TUN-008) | Allowlist por IP não funciona com destinos dinâmicos |
| D9 | Layout do repositório | `apps/` + `internal/`, dois módulos (`go.work`) | Padrão do dono; GUI com cgo isolada |
| D10 | Valores da baseline | Em claro dentro do age, nunca fora dele; sem hashes salgados | Hash de espaço pequeno não protege nada (§12.1) |

---

## 26. Critérios de aceitação da v1

Cada critério é um teste automatizado (`TestE2E_ACxx_*`) no netlab, salvo indicação. "Ambiente padrão" = netlab da §23.2 com WireGuard ativo e default route pelo túnel.

| ID | Cenário | Esperado |
|---|---|---|
| AC-01 | Guarda `off`; `curl --interface eth0 http://192.0.2.1` (ou socket equivalente no teste) | NET-001 CRITICAL em ≤ 1 s, com `proc.exe` atribuído e `confidence: high` |
| AC-02 | Guarda `off`; consulta DNS para `192.0.2.53` pela egress | DNS-001 CRITICAL; o qname decifrado com a chave sensível é igual ao enviado; sem a chave sensível, ele não aparece |
| AC-03 | IPv6 global com rota default em `eth0`, túnel só v4, `expect.ipv6: false` | NET-003 CRITICAL já no `arm` |
| AC-04 | Estrito; `ip link set wg0 down`; tráfego gerado para a internet simulada | TUN-001 CRITICAL; NET-002 registrado; o sniffer em `isp0` vê **zero** pacotes que não sejam DHCP/ARP/NDP |
| AC-05 | Estrito; o servidor WG muda de endpoint (segundo IP do ns "vpn") | Allowlist atualizado em ≤ 1 s; o túnel volta; nenhum CRITICAL; no máximo um NET-002 |
| AC-06 | Uma tabela `inet killswitch` com drop no output foi criada antes do `arm`; ela é apagada durante a sessão | TUN-004 CRITICAL |
| AC-07 | `tor` com ControlPort e cookie no ns "dut" (SKIP se não houver binário); depois, o tor é parado | Descoberta lista os guards (ou o endereço da bridge local de teste); ao parar, TUN-003 CRITICAL |
| AC-08 | `lethe panic` | Todo o tráfego é bloqueado em ≤ 200 ms (medido pelo sniffer); `unpanic` sem ack → recusado; sem passphrase → recusado; com tudo → liberado depois do re-check |
| AC-09 | Estrito; `kill -9` no daemon; tráfego gerado | Tabela permanece; sniffer vê zero vazamentos; `lethe cleanup` remove só as tabelas `lethe*` |
| AC-10 | Alterar 1 byte de qualquer segmento; truncar o último registro | Byte alterado → `verify` com exit 4 apontando o segmento e o `seq`; truncamento → `verify` OK com aviso `truncated_tail` |
| AC-11 | `lethe selftest` no netlab, nos modos `off` e `strict` | Todos os casos da §18.2 passam (RESP-001 com confirmação simulada) |
| AC-12 | Suíte e2e completa com checks ativos **desligados** | Sniffer da "internet" não vê nenhum pacote gerado pelo `lethe` fora do que os testes injetam |
| AC-13 | `nft list ruleset` (via biblioteca) antes do `arm` e depois do `disarm` | Idênticos, desconsiderando mudanças feitas de propósito por terceiros no teste |
| AC-14 | Peer com UID diferente conecta no socket | Recusado, `ipc.denied` no log |
| AC-16 | Estrito; o túnel não passa tráfego depois do arm (servidor WG parado) | O arm é desfeito em `guard.arm_confirm`; zero tabelas `lethe*`; exit code 6 com a causa; o log fecha com `reason: arm_unconfirmed` |
| AC-17 | Estrito sem túnel; `run --force --reason x` | Recusado com exit code 2 e a sugestão `--guard off`; nenhuma tabela aplicada |
| AC-18 | Guarda `off`; 5 provas erradas | SELF-006 CRITICAL; nenhuma tabela aplicada; ações sensíveis recusadas por 5 min. `kill -9` num daemon estrito seguido de `lethe status` como root → `lockdown` aponta `sudo lethe cleanup` |
| AC-15 | Manual (runbook): Debian 12, Ubuntu 24.04 e Fedora com Wi-Fi real, NM, Tor Browser e GUI em GNOME/Wayland e KDE | Checklist do runbook completo, com prints anexados ao relatório de release |

---

## 27. Roadmap pós-v1

### v1.1
- Atribuição de processo via eBPF (`cgroup/connect4/6`, `sendmsg4/6`) com `cilium/ebpf`, como o OpenSnitch faz; confiança alta mesmo para conexões curtas. Mapa eBPF no lugar do cBPF quando houver muitos endpoints.
- **Modo de isolamento por namespace** (opcional): mover a interface física para um namespace próprio, deixando só o túnel no namespace principal, no estilo do "ultimate kill switch" da documentação do WireGuard. É a garantia estrutural mais forte: sem rota física, não há vazamento possível. Exige integração com o cliente VPN.
- **IDN-001 — identidade dentro do túnel:** captura na interface do túnel só das consultas DNS e do SNI TLS, comparados com uma lista de domínios pessoais declarados (conta de e-mail, sync), com os nomes cifrados no log.
- DNS-005 (canário de DNS) + servidor autoritativo mínimo para a instituição.
- Selagem com integridade para frente no journal (§14.2).
- Regra de dois para `--force` e `unpanic`.
- Atalho global de pânico.

### v1.2
- Extensão de navegador (Firefox e Tor Browser) para checks de fingerprint coerentes com a persona (timezone do JS, idioma, WebRTC efetivo, canvas, WebGL).
- Várias personas por máquina.

### v2.0
- **Modo sensor:** o mesmo binário rodando num dispositivo em linha (Raspberry Pi, mini-PC) entre a máquina do operador e a rede, mandando eventos para a GUI por canal autenticado (WireGuard ponto a ponto). Fecha a limitação 22.1.
- Windows (ETW/Npcap para captura, WFP para o guarda).
- macOS (pf anchors, Network Extension).

---

# Parte III — Apêndices

## Apêndice A — Ferramentas existentes e o que reaproveitar

Pesquisa de nov/2026. **Não encontrei nenhuma ferramenta que junte, como o `lethe`, monitoramento passivo contínuo de vazamento, guarda fail-closed, coerência de persona e log com cadeia de custódia.** As que existem cobrem pedaços:

| Ferramenta | O que faz | Relação com o lethe | O que reaproveitar |
|---|---|---|---|
| **OpenSnitch** (open source, Go + eBPF) | Firewall de aplicação por processo | Concorre na atribuição de processo e no bloqueio por app; não sabe o que é túnel nem persona | Abordagem eBPF de atribuição (v1.1); ele trocou gobpf por `cilium/ebpf`; limitações documentadas para processos curtos |
| **Little Snitch for Linux** (lançado em abr/2026; daemon proprietário, eBPF) | Firewall de aplicação | Mesma categoria do OpenSnitch | Só referência de UX de alertas |
| **Portmaster** (Safing) | Firewall de aplicação + DNS + rede própria (SPN) | Sobreposição em DNS e bloqueio; é um produto inteiro | — |
| **Kill switch dos clientes** (Mullvad lockdown, Proton, IVPN) | Bloqueiam fora do túnel | São justamente o que o lethe vigia (TUN-004). Nenhum registra nem verifica de forma independente | — |
| **WireGuard "ultimate kill switch" (netns)** | Interface física num namespace separado | Garantia estrutural, sem monitoramento | Modo de isolamento (v1.1) |
| **vopono**, wg-netns, namespaced-openvpn | Rodam apps dentro de um namespace com VPN | Isolamento por app | Ideia para o modo de isolamento |
| **vortix** (Rust, TUI) | Gerencia WireGuard/OpenVPN; checa IPv6 e DNS contra o túnel; auditoria de sockets; modo daemon ainda esqueleto na 0.3 | O mais próximo em checks de configuração, mas sem captura nem guarda | Lista de checks de DNS/IPv6 para comparar |
| **vpndemon** | Mata processos quando a VPN cai (via D-Bus do NM); parado desde 2023 | Subconjunto mínimo do TUN-001 + `kill_processes` | — |
| **activevpn** (PyPI) | Testes de vazamento de IPv6 e DNS, com modo watch | Testes ativos pontuais | — |
| **ExpressVPN leak testing tools** (MIT, Python) | Suíte de testes de vazamento | Boa fonte de cenários de teste | Cenários para o netlab (§23) |
| **AnonSurf** (Parrot), Nipe, Kali-Whoami | Forçam o tráfego pelo Tor com iptables | Enforcement sem verificação, registro nem coerência | — |
| **Whonix, Qubes, Tails** | Isolamento por arquitetura | Complementares; o lethe roda no host deles ou ao lado | Referência de modelo de ameaça |
| **Zeek / Suricata** | IDS de rede genérico | Poderiam detectar NET-001 com regras, mas são pesados e não reagem | — |
| **ipleak.net, browserleaks, dnsleaktest** | Testes ativos no navegador | Pontuais; o operador pode usá-los na persona | Ideias para a extensão (v1.2) |
| **Canarytokens** (Thinkst) | Tokens DNS e HTTP | Referência para o DNS-005 | Desenho do servidor do canário |
| **journald Forward Secure Sealing** | Selagem de log com chave que evolui | Prior art da §14.2 | Esquema de chave evolutiva (v1.1) |

Conclusão: vale construir. Não vale reinventar o firewall de aplicação: para a atribuição exata (v1.1), reaproveite a abordagem e, se a licença permitir, código do OpenSnitch (GPL-3.0, o que obriga a avaliar a licença do lethe antes de copiar código; usar só a ideia não obriga). Como garantia mais forte, ofereça o modo de isolamento por namespace.

## Apêndice B — Correções em relação à v0.1

| # | Onde (v0.1) | Problema | Correção (v0.2) |
|---|---|---|---|
| 1 | §8.1 NET-001 | `PACKET_OUTGOING` foi tratado como opção que faz o socket receber só a saída; é um `sll_pkttype` | Filtro cBPF em `SKF_AD_PKTTYPE` (§8.1) |
| 2 | §10.3 tabela estrita | `oifname != @phys_ifaces accept` deixava passar interfaces novas (tethering, USB) entre o surgimento e a classificação: fail-open | Política `drop` com allowlist de interfaces; `unknown` = egress (§7.2, §11.3) |
| 3 | §10.3/§10.4 | Tabelas `inet` não pegam sockets AF_PACKET (raw) | Camada `netdev egress` (≥ 5.16) e `link_down` como fallback (§11.5) |
| 4 | §10.3 | Sem DHCPv6, sem MLDv2; endpoints sem protocolo; `timeout` podia derrubar o túnel em uso; log sem limite de taxa | §11.3 |
| 5 | §10.3 notas | `socket cgroupv2` fica obsoleto quando o serviço reinicia (o ID é resolvido ao carregar a regra) | Vigilância do cgroup e regeração (§11.2) |
| 6 | §7.3 / AC-5 | Endpoint novo bloqueado no estrito antes de ser descoberto (OpenVPN, comerciais) | Aprendizado via NFLOG + sock_diag do cliente VPN (§7.4) |
| 7 | §4.3 Tor | Snowflake/meek têm destinos dinâmicos e quebram o allowlist por IP; `entry-guards` sozinho não basta | §7.5, TUN-008 |
| 8 | §8.1 NET-011 | "Pelo túnel" não existe para Tor (não há interface); o resolvedor do sistema poderia vazar a própria consulta | SOCKS5h para Tor; bind + resolvedor preso ao túnel para VPN (§9.9) |
| 9 | §8.4 HOST-001 / §12.2 | `comm` é truncado em 15 caracteres: `telegram-desktop` e `chromium-browser` nunca casariam | `match: exe`; validador rejeita `comm` > 15 (§9.4, §13.2) |
| 10 | §11.1 baseline | Hash salgado de IPv4, MAC, SSID e hostname é trivialmente reversível, e o sal está no mesmo arquivo | Valores em claro só dentro do age; nunca fora dele (§12.1) |
| 11 | §13.2 log | Chave de sessão autogerada não prova nada sem âncora externa; assinatura só no fim (crash = sem assinatura) | Impressão digital registrada fora da máquina, checkpoints a cada 60 s (§14.2) |
| 12 | §13.3 log | Um arquivo age por segmento: o age só grava blocos de 64 KiB cheios ou no fechamento, então um crash perde o segmento inteiro | Registros selados um a um com XChaCha20-Poly1305 + fsync (§14.3) |
| 13 | §13.2 | "JSON canônico" sem definição | RFC 8785 (JCS) |
| 14 | §8.6 SELF-003 / §15.4 / §9.3 | Daemon root mandando notificação no D-Bus **de sessão**, `notify-send` (exec, o que contraria a §18.5), PipeWire de outro usuário: não funciona ou viola os princípios | Processo `lethe agent` com o UID do operador (§5.1); `link_down` e `lock_screen` via netlink/D-Bus |
| 15 | §16 IPC | Qualquer processo do UID do operador (o navegador comprometido) podia desarmar, reconhecer ou dar unpanic | Classes de método + desafio HMAC com a passphrase (§17.3) |
| 16 | §19 Stack | `gopacket/afpacket` usa cgo (contraria o binário estático); varredura de `/proc/net/*` em texto | `mdlayher/packet` / `antrea.io/packet`; sock_diag via `vishvananda/netlink` |
| 17 | §18.3 | Capabilities em Go são por thread; descartá-las com `syscall` deixa threads com privilégio | `libcap/cap` com psx (§19.3) |
| 18 | §18.3 | `ProtectSystem=strict` deixaria o `storage.dir` só leitura; faltava `CAP_IPC_LOCK` | `ReadWritePaths`, `CAP_IPC_LOCK` (§19.3) |
| 19 | §8.2 DNS-004 | inotify direto em `/etc/resolv.conf` perde substituições atômicas por symlink | Vigiar o diretório e o destino (§9.2) |
| 20 | §8.6 SELF-005 | Diferença entre relógio monotônico e de parede é ruidosa | `TFD_TIMER_CANCEL_ON_SET` + `CLOCK_BOOTTIME` (§9.6) |
| 21 | §8.3 TUN-002 | "Tráfego pendente" sem definição | `tx_bytes` subindo + handshake > 180 s (§9.3) |
| 22 | §8.1 NET-003 | Endereço global sem rota não é vazamento | C só com rota default; W só com endereço (§9.1) |
| 23 | §8.2 DNS-001 | Faltava DoQ (853/udp) | §8.3 |
| 24 | §8.1 (filtro) | EAPOL (rekey WPA) apareceria como vazamento no Wi-Fi | Exceção EAPOL (§8.1) |
| 25 | §17 selftest | ST-NET-001 não consegue passar no modo estrito (o pacote é dropado antes do tap) | Exceção temporária de 5-tupla (§18.1) |
| 26 | §21 AC-13 | "Ruleset idêntico" falha se o cliente VPN mexer nas próprias regras durante o teste | AC-13 desconsidera mudanças de terceiros; a verificação é sobre as tabelas `lethe*` |
| 27 | §19 | Go ≥ 1.23 desatualizado | Última estável fixada no `.mise.toml` (1.27 em nov/2026) |
| 28 | — (lacunas) | Faltavam: checagem de conectividade do NM presa à interface, hostname no DHCP, GeoClue (BSSIDs pelo túnel), iptables-legacy, interfaces empilhadas (vlan/bond/bridge) | NET-013, NET-014, HOST-009, TUN-007, §7.2 |
| 29 | §24 | Questões em aberto bloqueavam a implementação | Decisões padrão D1–D10 (§25) |
| 30 | — | Não havia plano de execução, estratégia de teste reproduzível nem trava contra derrubar a rede da máquina de desenvolvimento | Parte II (§23–§26) |

## Apêndice C — Glossário

| Termo | Significado |
|---|---|
| Interface egress | Interface cujo tráfego chega ao fio sem passar por um túnel (§7.2) |
| Endpoint | IP, protocolo e porta do servidor do túnel mais externo (servidor VPN, guard ou bridge do Tor) |
| Allowlist | Endpoints + exceções de enlace; o que pode sair pela egress |
| Guarda | Tabelas nftables do lethe (§11) |
| Pânico | Estado com `block_all` ativo |
| Ação sensível | Método IPC que exige prova da passphrase (§17.3) |
| Âncora | Impressão digital da chave de sessão registrada fora da máquina (§14.2) |
| Netlab | Topologia de network namespaces usada nos testes (§23.2) |
| CINZA | Visibilidade degradada; nunca equivale a "seguro" |
