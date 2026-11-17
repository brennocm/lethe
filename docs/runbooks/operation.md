# Operação

Roteiro de uma operação pelo painel do lethe (`lethe-gui`). Cada passo tem o equivalente no terminal, para máquinas sem desktop. O modo serviço à mão está em `service-mode.md`.

## Antes (uma vez por máquina e por identidade)

1. **Instale** os pacotes `lethe` e `lethe-gui` (`README.md`) e confira o binário: `lethe version` deve mostrar o SHA-256 das notas da release.
2. **Abra o lethe** pelo menu de aplicativos. Sem perfil, o painel mostra **Primeiro uso**.
3. Com a VPN **desligada**, na rede real:
   - preencha a identidade da operação (ou deixe os valores sugeridos);
   - clique em **Descobrir o IP público**. O lethe recusa se houver túnel ligado, porque o IP do túnel não é o seu;
   - digite a passphrase duas vezes e clique em **Criar perfil**.

   Isso cria `~/lethe/profile.yaml` e `~/lethe/baseline.age`. Sem chaves para gerenciar: o único segredo é a passphrase. No terminal: `lethe setup`.
4. **Guarde a passphrase fora da máquina.** Sem ela não se reconhece alerta CRITICAL, não se sai do pânico e não se encerra a sessão pelo painel.
5. Outras redes reais em que você trabalha (casa, escritório, café): conecte-se a cada uma **sem** a VPN e clique em **Registrar a rede atual**. O IP e os DNS dela passam a contar como vazamento a partir da próxima sessão.
6. **Iniciar o lethe:** com o serviço parado, o painel diz "O lethe não está rodando" e oferece o botão. O sistema pede a senha de administrador. No terminal: `sudo systemctl enable --now lethed@$USER`, ou no modo portátil `sudo lethe run -p ~/lethe/profile.yaml`.
7. **Primeira vez nesta máquina:** inicie uma sessão em *Só observar* com a VPN ligada e rode o **Selftest** completo. A proteção *Estrita* só aparece depois de um selftest completo aprovado aqui, com menos de 24 h.

## Começo da operação

1. Ligue a VPN (ou o Tor).
2. No painel, escolha a proteção, digite a passphrase e clique em **Iniciar sessão**:
   - o preflight roda primeiro. Se der FAIL, nada é aplicado e o painel diz o que corrigir;
   - na estrita, o lethe espera o túnel passar tráfego (`guard.arm_confirm`). Se não passar, desfaz tudo e explica;
   - se sobraram regras de uma queda anterior, a sessão é recusada até você usar **Liberar a rede** (`crash-recovery.md`).
3. **Anote fora da máquina a impressão digital** da chave da sessão, que aparece no cabeçalho do painel. A verificação do log usa essa anotação.
4. Confira a primeira linha (o veredito) e a **rota**: esta máquina, o túnel e onde a web vê você (IP, cidade e país). **Verificar agora** refaz a consulta; **Testar vazamento de DNS** confere quem resolve seus nomes (explica antes de rodar).

No terminal: `sudo lethe run -p PERFIL` (portátil) ou `lethe arm -p PERFIL` (serviço); `--tui` abre a TUI.

## Durante

| Sinal | O que fazer |
|---|---|
| Verde | Coberto. Nada a fazer |
| Amarelo (WARNING) | Leia o "o que fazer" do alerta e clique em **Reconhecer** (sem passphrase) |
| Vermelho (CRITICAL), tela cheia | **Pare de usar a identidade.** Leia a causa. Corrija, ou clique em **Pânico** se não souber o motivo. O alerta só fecha com motivo e passphrase |
| Cinza | Um sensor parou: o lethe não está vendo aquela parte. Trate como risco até voltar |
| Pânico | A rede está bloqueada de propósito. O quadro de bloqueio diz o quê, por quê e como sair. Reconheça os CRITICAL, corrija a causa e clique em **Sair do pânico**, que confere túnel, rotas, IPv6 e DNS antes de liberar |

- **Pânico** fica sempre visível no rodapé (e no menu da bandeja). Ele bloqueia na hora, sem passphrase, depois de uma confirmação.
- Sem ícone na bandeja (GNOME sem a extensão AppIndicator), o painel é a GUI inteira: fechá-lo encerra a GUI, não a sessão. Abra de novo pelo menu; os alertas continuam chegando como notificações.
- No terminal: `lethe status`, `lethe ack ID [--reason "..."]`, `lethe panic`, `lethe unpanic`.

## Fim

1. Clique em **Encerrar sessão** e digite a passphrase. As regras saem, o log é fechado e assinado e o relatório é gerado. No terminal: Ctrl-C no `run`, ou `lethe disarm`.
2. Se a sessão está em pânico, **Encerrar sessão** também funciona (pede a passphrase) e libera a rede ao encerrar.
3. Abra **Relatórios** e confira a sessão. Para o caso, verifique o log com a impressão digital anotada (`session-verification.md`).
4. Desligue a VPN só depois de encerrar.

Se a rede ficar bloqueada sem sessão, ou se o daemon morrer, siga `crash-recovery.md`.
