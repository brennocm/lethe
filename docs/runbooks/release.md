# Release e entrega (para o dono do projeto)

O lethe é uma ferramenta local, não um serviço: "deploy" aqui é **gerar, assinar e publicar no repositório interno** os binários e pacotes, para que operadores os instalem e confiram (ADR 0002). Este guia separa o que a automação já faz do que **só o dono** pode fazer: chaves, repositório interno, licença e decisões institucionais.

Nenhuma chave, senha ou endereço interno vai para este repositório, para issues ou para o chat. Quando um comando abaixo pede segredo, ele pergunta de forma interativa.

## 1. Estado

### Feito e verificado (pela automação)

| Item | Evidência |
|---|---|
| M0–M15 implementados, mais as revisões do ADR 0015 (GUI como caminho principal) | `AGENTS.md` (seção Estado), ADRs 0001–0015 |
| Lint, vet, unit, race, deadcode, govulncheck, matriz de rastreabilidade, licenças | `mise run check:all` verde |
| E2E completo no netlab, com seccomp em enforce, AC-12 incluído | `mise run e2e` verde (AC-07 dá SKIP sem o binário `tor`) |
| Build reprodutível: dois builds do mesmo commit dão bytes idênticos (binários, `.deb`, `.rpm`) | `mise run release:repro` |
| Pacotes deb/rpm com as unidades systemd (`lethed`, `lethed@`, `lethe-cleanup`, agente); `lethe-gui` com a entrada no menu, o ícone e as bibliotecas de execução declaradas; SBOM CycloneDX; `SHA256SUMS` | `mise run release -- VERSION --gui`; conteúdo conferido com `dpkg-deb -c` |
| Binário `lethe-gui` compilado com cgo | `mise run build:gui` no WSL2 (Ubuntu 24.04), com os headers instalados por `scripts/gui-deps`; janela aberta no WSLg |
| Runbooks de operação, recuperação, verificação, modo serviço e aceitação manual | `docs/runbooks/` |

### Feito, mas sem verificação aqui

- **`scripts/gui-deps` fora do Debian/Ubuntu:** os nomes de pacote de Fedora, Arch e openSUSE não foram testados numa máquina real. O script confere no fim, pelo `pkg-config`, o que ainda falta.
- **Botões que falam com o systemd** (Iniciar o lethe, Liberar a rede): testados contra dublês do D-Bus; o polkit e o systemd reais só no AC-15 (seção 0 do `manual-acceptance.md`).
- **Pacotes instalados de verdade** (`apt install`, `dnf install`) e as unidades sob systemd real: o conteúdo foi conferido com `dpkg-deb -c`, e as unidades com `systemd-analyze verify`.
- **AC-07 (Tor real) e AC-15 (Wi-Fi, NetworkManager, Tor Browser, GUI em GNOME/KDE):** manuais, em `ac07-tor.md` e `manual-acceptance.md`.

### Pendente com o dono

1. Escolher e adicionar a **licença** do lethe (não há `LICENSE`). As dependências estão em `docs/THIRD_PARTY.md`: nenhuma obriga GPL (a libcap é dupla, BSD-3-Clause ou GPL-2.0, e o lethe usa a BSD).
2. Fixar e embutir a **base geo** (seção 4.2).
3. Criar as **chaves de assinatura** e o **repositório interno** (seções 4.3 e 4.6).
4. Criar o **remote Git** institucional e fixar as actions do CI por SHA antes do primeiro push (seção 4.1).
5. Rodar a **aceitação manual** (AC-07 e AC-15) em máquinas de teste.

### Limites conhecidos no lançamento

- Os sinais D-Bus do DNS-004 (resolved/NM) não estão implementados. DNS-002 e DNS-003 releem o resolved a cada descoberta (5 s), então a mudança é vista em até 5 s.
- Sem a base geo (`pins.json` vazio), TUN-006 e o país do NET-011/PER-001 ficam inativos.
- A allowlist do seccomp só foi exercida nos caminhos do e2e. Uma syscall fora dela mata o daemon (`signal=SYS`): a rede fica fechada e o `service-mode.md` explica a coleta.
- No GNOME/Wayland a janela de alerta pode não ficar por cima; a notificação e o som sempre acompanham o alerta.
- No GNOME sem a extensão AppIndicator não há ícone na bandeja: o painel é a GUI inteira, e fechá-lo encerra a GUI (não a sessão).
- `bridge lethe` e `socket cgroupv2` não rodam no kernel do WSL2. Valide-os nas distros reais (AC-15).

## 2. Contas, chaves e custos

| O quê | Para quê | Quem cria | Custo |
|---|---|---|---|
| Chave **minisign** de release (ou identidade Sigstore/cosign) | Assinar `SHA256SUMS`; operadores conferem antes de instalar | Dono, numa máquina off-line ou num token | zero |
| Chave **GPG** do repositório | Assinar o repositório apt (`Release`/`InRelease`) e os `.rpm` | Dono | zero |
| Repositório interno apt/dnf (aptly, reprepro, Pulp, Nexus ou o que a instituição usa) | Distribuição. **Nunca** por download público na hora da operação (spec §19.2) | Dono / TI da instituição | o da infraestrutura existente |
| Remote Git institucional com CI (GitHub, GitLab ou Forgejo interno) | CI: check:all, e2e, gui, release:repro | Dono | o do plano existente |
| Conta DB-IP | Não é preciso: a base Lite é pública (CC BY 4.0, com atribuição no `THIRD_PARTY.md`) | — | zero |

O CI **não** recebe as chaves de assinatura. Ele só prova o build; quem assina é o dono, com os artefatos que ele mesmo compilou e comparou.

## 3. Inventário de configuração

| Nome | Para quê | Onde fica | Obrigatório na 1ª release |
|---|---|---|---|
| `scripts/update-geo/pins.json` (mês + SHA-256) | Fixar a base geo embutida | No repositório (não é segredo) | Sim, ou a release sai sem geo (TUN-006 e o país inativos) |
| Chave minisign secreta (`*.key`) | Assinatura | Fora do repositório, off-line, com senha | Sim |
| Chave minisign pública (`lethe.pub`) | Conferência pelos operadores | Publicada no repositório interno e nas notas | Sim |
| Chave GPG do repositório | Repositório apt/dnf | Fora do repositório | Sim, se houver repositório de pacotes |
| `SOURCE_DATE_EPOCH` | Datas reprodutíveis | Calculado do commit pelo `scripts/release` | Automático |

## 4. Passo a passo

### 4.1 Remote e CI (uma vez, cerca de 30 min)

1. **Objetivo:** CI rodando no repositório institucional.
2. **Ação:**
   - crie o repositório vazio no Git institucional;
   - adicione o remote: `! git remote add origin <URL>`;
   - em `.github/workflows/ci.yml`, troque `actions/checkout@v4` e `jdx/mise-action@v2` pelo SHA completo do commit de cada versão (o comentário no arquivo pede isso);
   - faça o commit e o push: `! git push -u origin main`.
3. **Esperado:** jobs `check`, `gui`, `release` e `e2e` verdes.
4. **Se falhar:** o `e2e` precisa de `sudo` no runner e do `wireguard-tools`. O `gui` instala os headers com `scripts/gui-deps --yes`; se um nome de pacote mudou na distro do runner, o script diz qual módulo do `pkg-config` ainda falta.

### 4.2 Base geo (a cada release, cerca de 10 min)

1. **Objetivo:** embutir a DB-IP Lite de um mês, conferida por hash.
2. **Ação:**
   - `go run ./scripts/update-geo -print -month 2026-11`: baixa e mostra os SHA-256, sem gravar nada;
   - confira os hashes com uma segunda fonte (outra rede, ou outra pessoa rodando o mesmo comando);
   - grave o mês e os hashes em `scripts/update-geo/pins.json` e faça o commit (`chore(geo): pin DB-IP 2026-11`);
   - `go run ./scripts/update-geo` grava os `.mmdb` em `internal/geo/data/`, fora do git.
3. **Verificar:** depois do build, `dist/VERSION/linux_amd64/lethe version` mostra em `geo db` a data da base, e não `none`.
4. **Se falhar:** hash diferente significa arquivo diferente do fixado. Não troque o pin sem saber por quê.

### 4.3 Chaves (uma vez, cerca de 20 min)

- minisign:
  - `! minisign -G -p lethe.pub -s ~/offline/lethe.key` pede a senha de forma interativa;
  - guarde o `.key` e a senha separados e off-line, com uma cópia de segurança;
  - publique o `lethe.pub` no repositório interno.
- GPG do repositório: `! gpg --full-generate-key` (ed25519, com validade). Exporte a pública para os clientes apt/dnf.
- Ative a 2FA no Git institucional e no repositório de pacotes; guarde os códigos de recuperação off-line.

### 4.4 Gerar a release (a cada release, cerca de 15 min)

1. Atualize as notas, numa seção da tag ou num `CHANGELOG`.
2. Prove que a árvore está limpa e passa: `mise run check:all` e `sudo -E env "PATH=$PATH" mise run e2e`.
3. Crie a tag: `! git tag -s v0.1.0 -m "lethe 0.1.0"`.
4. Prove a reprodutibilidade: `mise run release:repro`. Deve terminar com `two builds of <commit> are identical`.
5. Gere a release: `mise run release -- 0.1.0`, ou com `--gui` numa máquina com os headers.
   - `dist/0.1.0/` deve ter: `linux_{amd64,arm64}/lethe`, `lethe_0.1.0-1_{amd64,arm64}.deb`, `lethe-0.1.0-1.{x86_64,aarch64}.rpm`, `lethe.cdx.json`, `lethe-gui.cdx.json` e `SHA256SUMS`.
   - O script recusa uma árvore modificada; o `--allow-dirty` é só para teste, nunca para release.
6. **Confira com um segundo build independente:** o CI (job `release`) ou outra máquina, a partir da tag. Os `SHA256SUMS` sem as linhas `.cdx.json` precisam ser iguais. Assine só se forem.

### 4.5 Assinar (a cada release, cerca de 5 min, só o dono)

1. `! minisign -S -s ~/offline/lethe.key -m dist/0.1.0/SHA256SUMS -t "lethe 0.1.0 $(git rev-parse HEAD)"`
2. Para os rpm: `! rpm --addsign dist/0.1.0/*.rpm`, com a chave GPG configurada no `~/.rpmmacros`.
   - Isso muda os bytes dos `.rpm`: gere de novo o `SHA256SUMS` dos rpm assinados (`cd dist/0.1.0 && sha256sum *.rpm`, atualizando as linhas) **antes** de assinar com minisign.
   - Ou: assine os rpm primeiro e rode o minisign por último.
3. **Verificar:** `minisign -V -p lethe.pub -m dist/0.1.0/SHA256SUMS`, e depois `cd dist/0.1.0 && sha256sum -c SHA256SUMS`.

### 4.6 Publicar no repositório interno (a cada release, cerca de 15 min)

1. **apt:** importe os `.deb` (por exemplo `aptly repo add lethe dist/0.1.0/*.deb`, depois `aptly publish update`, que assina com a chave GPG).
2. **dnf:** copie os `.rpm` assinados e rode `createrepo_c`; assine o `repomd.xml` se a política exigir.
3. Publique também `SHA256SUMS`, `SHA256SUMS.minisig`, os SBOMs, o `lethe.pub` e as notas.
4. **Verificar numa máquina de teste limpa:**
   - `apt install lethe` (ou `dnf install lethe`);
   - `lethe version`: o SHA-256 deve ser igual ao de `linux_amd64/lethe` no `SHA256SUMS`;
   - `systemctl cat lethed@$USER` deve mostrar a unidade;
   - o lethe deve aparecer no menu de aplicativos e abrir o painel.

### 4.7 Aceitação antes de liberar aos operadores (cerca de 1 dia)

- Rode o `manual-acceptance.md` (AC-15) em Debian 12, Ubuntu 24.04 e Fedora, e o `ac07-tor.md`.
- Anexe os prints, os `lethe report` e os `lethe verify` às notas.
- Um item sem marcação bloqueia a release, salvo exceção registrada com o motivo.

## 5. Checklist de liberação

- [ ] Licença do lethe decidida e presente no repositório e no pacote.
- [ ] `pins.json` preenchido e conferido por uma segunda fonte; `lethe version` mostra a data da base geo.
- [ ] `check:all`, `e2e` e `release:repro` verdes no commit da tag.
- [ ] Dois builds independentes com `SHA256SUMS` iguais (fora os SBOMs).
- [ ] `SHA256SUMS` assinado; a assinatura confere com o `lethe.pub` publicado.
- [ ] rpm e repositório apt assinados com GPG.
- [ ] Chaves off-line, com cópia, senha guardada separada e 2FA nas contas.
- [ ] CI sem acesso às chaves; actions fixadas por SHA.
- [ ] Instalação limpa conferida em cada distro-alvo.
- [ ] AC-07 e AC-15 completos e anexados.
- [ ] Notas da release com os limites conhecidos (seção 1).

## 6. Rollback

- **Release ruim no repositório:**
  - republique a versão anterior;
  - no apt, os operadores podem fixá-la com `apt install lethe=<versão anterior>-1`;
  - no dnf, `dnf downgrade lethe`.
- **Retirar uma versão:**
  - remova-a do repositório interno e publique um aviso com o motivo e o hash;
  - não reaproveite o número da versão.
- **Chave de assinatura comprometida:**
  - revogue-a e gere outra;
  - assine de novo as versões vigentes;
  - avise os operadores para trocar o `lethe.pub`.
- **Na máquina do operador, se o lethe bloquear a rede:** **Liberar a rede** no painel, ou `sudo lethe cleanup`, que remove só as tabelas `lethe*`, ou reinicie a máquina (`crash-recovery.md`). Não há migração de dados: as sessões antigas continuam legíveis pelo `lethe verify`/`report` de qualquer versão com o mesmo formato de log.

## 7. Depois da release

- **Primeira semana:** colete dos operadores os `signal=SYS` (seccomp) e os falsos positivos, com os relatórios **sem** `--include-sensitive`.
- **A cada mês ou release:**
  - `govulncheck` (já no `check:all`);
  - atualização de dependências, e depois `mise run third-party -- -write`, revisando a tabela de licenças;
  - nova base geo (seção 4.2).
- **A cada ano:** renovação das chaves GPG com validade; um teste de verificação de uma sessão antiga com a versão atual.
- Toda mudança manual no processo volta para este arquivo.
