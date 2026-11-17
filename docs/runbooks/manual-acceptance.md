# Teste de aceitação manual (AC-15)

O que o netlab não cobre: Wi-Fi real, NetworkManager, o Tor Browser e a GUI em desktops de verdade. Rode este roteiro antes de cada release, em:

- Debian 12;
- Ubuntu 24.04;
- Fedora (a versão atual).

Use máquinas de teste, nunca a máquina de operação. Anexe ao relatório de release os prints e a saída de `lethe report` de cada máquina.

## Preparação (uma vez por máquina)

1. Instale os pacotes da release (`.deb`/`.rpm`; o `lethe-gui` puxa as bibliotecas gráficas) ou copie `lethe` e `lethe-gui` para a mesma pasta, com dono root e permissão `0755`. Confira o hash com `lethe version` e as notas da release.
2. Tenha à mão:
   - uma VPN WireGuard de teste com DNS próprio;
   - o Tor (o daemon do sistema e o Tor Browser);
   - duas redes Wi-Fi: a "real" e outra para trocar.
3. Crie o perfil e a baseline pelo **Primeiro uso** do painel (seção 0), **sem** a VPN, na rede real. No terminal, o equivalente é `lethe setup`.
4. Inicie uma sessão em *Só observar*, rode o **Selftest** completo e encerre. O selftest completo precisa passar antes de qualquer teste em estrito; até lá, o painel nem oferece a estrita.

## 0. Do zero, pelo painel (uma vez por distro, GNOME e KDE)

| # | Passo | Esperado | ok |
|---|---|---|---|
| 0.1 | Procurar "lethe" no menu de aplicativos | A entrada aparece com o ícone do lethe e abre o painel | ☐ |
| 0.2 | Painel sem perfil, VPN desligada | Formulário **Primeiro uso**: gateway, DNS e tipo de túnel já preenchidos pela leitura local; nenhuma consulta à rede ainda | ☐ |
| 0.3 | **Descobrir o IP público** com a VPN ligada | Recusa, explicando que o IP do túnel não é o seu | ☐ |
| 0.4 | O mesmo com a VPN desligada; passphrase duas vezes; **Criar perfil** | `~/lethe/profile.yaml` e `~/lethe/baseline.age` criados; o painel passa ao início de sessão | ☐ |
| 0.5 | Serviço parado | Veredito "O lethe não está rodando" e o botão **Iniciar o lethe** | ☐ |
| 0.6 | **Iniciar o lethe** | O polkit pede a senha de administrador; o painel conecta sozinho; `systemctl status lethed@$USER` ativo | ☐ |
| 0.7 | O mesmo, cancelando o polkit | O painel diz que não iniciou; nada muda | ☐ |
| 0.8 | Sem a VPN, numa segunda rede: **Registrar a rede atual** | Rede registrada (o painel diz quantas a baseline tem); repetir o mesmo nome é recusado | ☐ |
| 0.9 | Sessão armada | O cabeçalho mostra a impressão digital da chave, selecionável; é a mesma do `lethe status` | ☐ |
| 0.10 | Encerrar a sessão e abrir **Relatórios** | A sessão aparece no topo com o relatório | ☐ |
| 0.11 | Arme em estrito e mate o daemon (`sudo kill -9 $(pidof lethe)`) | O systemd o reinicia; o painel mostra as tabelas que sobraram e **Liberar a rede**; Iniciar sessão é recusado | ☐ |
| 0.12 | **Liberar a rede** | O polkit pede a senha; a rede volta; `sudo nft list tables` sem `lethe*` | ☐ |
| 0.13 | Modo portátil (`sudo lethe run`), estrito, `kill -9` | Com o daemon parado, o painel mostra **Liberar a rede** ao lado de **Iniciar o lethe** | ☐ |
| 0.14 | Serviço parado, um socket de outro usuário em `/run/user/$UID/lethe/lethe.sock` | O painel não conecta a ele; `lethe status` recusa ("not the daemon") | ☐ |

## 1. GUI — GNOME/Wayland, GNOME/X11, KDE/Wayland e KDE/X11

Para cada combinação (escolha a sessão na tela de login):

| # | Passo | Esperado | ok |
|---|---|---|---|
| 1.1 | `sudo lethe run -p PERFIL --guard off` com a VPN ligada | A GUI abre sozinha (unidade transitória `lethe-gui-*.service` em `systemctl --user list-units 'lethe-gui*'`), o ícone aparece na bandeja e o painel mostra ARMED e a impressão digital da sessão | ☐ |
| 1.2 | Clicar no ícone da bandeja | Menu com o estado e o número de alertas, Abrir painel, Pânico, Selftest e Encerrar sessão | ☐ |
| 1.3 | Fechar o painel pelo X | Com bandeja: o painel some e a bandeja continua; "Abrir painel" o traz de volta. Sem bandeja (GNOME sem AppIndicator): a GUI fecha, a sessão segue armada e o menu de aplicativos a abre de novo | ☐ |
| 1.4 | Desligar a VPN (`wg-quick down`) | Em ≤ 500 ms aparece o alerta vermelho em tela cheia do TUN-001/NET-004, com o som e uma notificação crítica do agente. O ícone fica vermelho e mostra o contador | ☐ |
| 1.5 | No alerta: Esc, Alt+F4 e o X | Nada fecha o alerta | ☐ |
| 1.6 | Reconhecer sem motivo, depois sem passphrase | Nada acontece | ☐ |
| 1.7 | Reconhecer com motivo e a passphrase errada | Mensagem de prova rejeitada; o alerta continua | ☐ |
| 1.8 | Reconhecer com a passphrase certa | O alerta sai e o painel mostra "Alerta reconhecido". `lethe report` tem `alert.ack` e um `response.executed` do `alert_fullscreen` com `reported_by: gui` | ☐ |
| 1.9 | Só no X11: abrir o diálogo de reconhecer | Aparece o aviso de que o teclado pode ser lido no X11 | ☐ |
| 1.10 | Botão Pânico → confirmar Pânico (guarda `strict`, rode de novo com `--guard strict`) | A rede para; o painel mostra o bloqueio e o botão "Sair do pânico". Sair do pânico pede a passphrase e só libera com o túnel de pé | ☐ |
| 1.11 | Selftest → Rápido | Resultado no painel, em cerca de 1 minuto | ☐ |
| 1.12 | Encerrar sessão (passphrase) | Sessão encerrada; o painel mostra READY; `nft list ruleset` sem tabelas `lethe*` | ☐ |
| 1.13 | `sudo lethe run -p PERFIL --no-gui` | Nenhuma GUI abre; os alertas chegam pelas notificações | ☐ |
| 1.14 | Matar a GUI (`systemctl --user stop 'lethe-gui-*'`) com a sessão armada | A sessão segue armada; os alertas continuam pelas notificações | ☐ |

Anote, para cada desktop, se a janela de alerta ficou **acima de tudo** e se ganhou o foco. No GNOME/Wayland é esperado que não fique (spec §16.4): por isso a notificação e o som sempre acompanham o alerta.

## 2. TUI

| # | Passo | Esperado | ok |
|---|---|---|---|
| 2.1 | `sudo lethe run -p PERFIL --tui`, desligar a VPN | Tela vermelha inteira e sino a cada `ui.sound_repeat` | ☐ |
| 2.2 | `q` e Esc durante o alerta | Nada acontece | ☐ |
| 2.3 | `a`, motivo, passphrase | O alerta sai e a tela principal volta | ☐ |
| 2.4 | `q` fora do alerta | A TUI fecha; a sessão segue armada ("Ctrl-C desarma") | ☐ |

## 3. Wi-Fi e NetworkManager

| # | Passo | Esperado | ok |
|---|---|---|---|
| 3.1 | Armado, trocar para a outra rede Wi-Fi | NET-007 | ☐ |
| 3.2 | Rede Wi-Fi da baseline com autoconnect | HOST-008 no preflight | ☐ |
| 3.3 | MAC de fábrica na interface Wi-Fi | NET-008 | ☐ |
| 3.4 | Checagem de conectividade do NM ligada | NET-013 | ☐ |
| 3.5 | DHCP mandando o hostname (`dhcp-send-hostname=true`) | NET-014 | ☐ |
| 3.6 | Plugar um cabo ou um celular em USB tethering | NET-006 e, se houver rota, NET-004 | ☐ |

## 4. Tor e Tor Browser

| # | Passo | Esperado | ok |
|---|---|---|---|
| 4.1 | Perfil `egress.type: tor`, Tor do sistema rodando | Preflight OK; `discover --json` mostra `tor.socks` | ☐ |
| 4.2 | `sudo lethe run` com checks ativos ligados | `status --json` traz `exit.path: tor` e o país da saída (base geo presente) | ☐ |
| 4.3 | Abrir o Tor Browser e navegar | Nenhum NET-001/DNS-001 | ☐ |
| 4.4 | Navegador comum com WebRTC ligado, numa página de chamada | NET-012 ou PER-002 | ☐ |
| 4.5 | Parar o Tor | TUN-003 | ☐ |

## Fechamento

- Rode `lethe report` e `lethe verify` da última sessão de cada máquina e anexe-os.
- Qualquer ☐ sem marcação bloqueia a release, ou exige uma exceção registrada nas notas da release com o motivo.
