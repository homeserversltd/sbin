"""Synchronize configured games into Steam shortcuts and artwork."""
#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, pwd, re, shlex, shutil, subprocess, time, urllib.parse, urllib.request, zlib
from pathlib import Path
import vdf
from PIL import Image, ImageDraw, ImageFont

LIBRARY_ROOT = Path('/home/owner/Games')
ARTWORK_ROOT = LIBRARY_ROOT / 'artwork'
RUNNERS_PATH = Path('/etc/arch-game-sync/runners.json')
PROVIDER_ENV = Path('/etc/arch-game-sync/providers.env')
STEAM_HOME = Path('/home/owner')
RECEIPT_DIR = LIBRARY_ROOT / 'receipts'
OWNER_USER = 'owner'
BIOS_ROOT = LIBRARY_ROOT / 'bios'
BIOS_REQUIREMENTS = {
    'ps1': {'kind': 'user-bios-required', 'paths': ['ps1/scph5500.bin', 'ps1/scph5501.bin', 'ps1/scph5502.bin'], 'policy': 'user-owned PlayStation BIOS files only; never bundled'},
    'sega-cd': {'kind': 'user-bios-required', 'paths': ['sega-cd/bios_CD_U.bin', 'sega-cd/bios_CD_E.bin', 'sega-cd/bios_CD_J.bin'], 'policy': 'user-owned Sega-CD BIOS files only; never bundled'},
}

TGDB_PLATFORM_IDS = {'gba': '5', 'snes': '6', 'nes': '7', 'genesis': '18'}


def run(argv, timeout=120):
    proc = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    return {'argv': argv, 'exit_code': proc.returncode, 'ok': proc.returncode == 0, 'stdout_tail': proc.stdout[-1200:], 'stderr_tail': proc.stderr[-1200:]}


def clean_game_title(appname: str) -> str:
    title = appname
    for suffix in [' (GBA)', ' (SNES)', ' (NES)', ' (GENESIS)', ' (Genesis)', ' (DOS)', ' (PS1)']:
        title = title.replace(suffix, '')
    return re.sub(r'\([^)]*\)', '', title).strip()


def infer_region(path: Path) -> str:
    text = path.name.lower()
    if 'usa' in text or '(u)' in text or 'ntsc-u' in text:
        return 'usa'
    if 'europe' in text or '(e)' in text or 'pal' in text:
        return 'europe'
    if 'japan' in text or '(j)' in text:
        return 'japan'
    if 'world' in text:
        return 'world'
    return 'unknown'


def title_from_path(path: Path, system: str) -> str:
    title = path.stem
    for token in [' (USA)', ' (Europe)', ' (World)', ' (Japan)', ' (En,Fr,De,Es,It)', ' (En)']:
        title = title.replace(token, '')
    return f'{title.strip()} ({system.upper()})'


def slugify(text: str) -> str:
    value = re.sub(r'\([^)]*\)', '', text.lower())
    return re.sub(r'[^a-z0-9]+', '-', value).strip('-') or 'game'


def read_provider_env() -> dict[str, str]:
    env: dict[str, str] = {}
    if PROVIDER_ENV.exists():
        for raw in PROVIDER_ENV.read_text(encoding='utf-8', errors='ignore').splitlines():
            line = raw.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            try:
                parsed = shlex.split(value, comments=False, posix=True)
            except ValueError:
                continue
            if parsed:
                env[key.strip()] = parsed[0]
    return env


def http_json(url: str, headers: dict[str, str] | None = None, timeout: int = 25) -> dict:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode('utf-8'))


def download_file(url: str, out: Path, headers: dict[str, str] | None = None, timeout: int = 40) -> bool:
    try:
        req = urllib.request.Request(url, headers=headers or {'User-Agent': 'arch-game-sync/0.1'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = response.read()
        if len(data) < 512:
            return False
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        Image.open(out).verify()
        return True
    except Exception:
        try:
            out.unlink(missing_ok=True)
        except Exception:
            pass
        return False


def appid_signed(exe: str, name: str) -> int:
    raw = (zlib.crc32((exe + name).encode('utf-8')) | 0x80000000) % 4294967296
    return raw - 4294967296 if raw >= 2147483648 else raw


def appid_unsigned(value: int) -> int:
    return value + 4294967296 if value < 0 else value


def ensure_steam_dir(path: Path):
    info = pwd.getpwnam(OWNER_USER)
    created = []
    current = path
    while not current.exists():
        created.append(current)
        current = current.parent
    path.mkdir(parents=True, exist_ok=True)
    for directory in reversed(created):
        os.chown(directory, info.pw_uid, info.pw_gid)
    return info, list(reversed(created))


def find_shortcuts_file():
    candidates = sorted((STEAM_HOME/'.local/share/Steam/userdata').glob('*/config/shortcuts.vdf'))
    if candidates:
        return candidates[0]
    default = STEAM_HOME/'.local/share/Steam/userdata/75467976/config/shortcuts.vdf'
    ensure_steam_dir(default.parent)
    return default


def steam_grid_dir(shortcuts_path: Path) -> Path:
    path = shortcuts_path.parent / 'grid'
    ensure_steam_dir(path)
    return path


def read_shortcuts(path: Path):
    if not path.exists() or path.stat().st_size == 0:
        return {'shortcuts': {}}
    with path.open('rb') as handle:
        return vdf.binary_load(handle)


def write_shortcuts(path: Path, data):
    info, _ = ensure_steam_dir(path.parent)
    tmp = path.with_suffix('.vdf.tmp')
    with tmp.open('wb') as handle:
        vdf.binary_dump(data, handle)
    os.chown(tmp, info.pw_uid, info.pw_gid)
    os.chmod(tmp, 0o644)
    tmp.replace(path)


def load_font(size: int):
    for candidate in ['/usr/share/fonts/TTF/DejaVuSans-Bold.ttf', '/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf', '/usr/share/fonts/TTF/LiberationSans-Bold.ttf']:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size=size)
    return ImageFont.load_default()


def fit_text(draw: ImageDraw.ImageDraw, text: str, max_width: int, start_size: int, min_size: int = 24):
    for size in range(start_size, min_size - 1, -2):
        font = load_font(size)
        words = text.split()
        lines, current = [], ''
        for word in words:
            trial = (current + ' ' + word).strip()
            if draw.textbbox((0, 0), trial, font=font)[2] <= max_width or not current:
                current = trial
            else:
                lines.append(current); current = word
        if current:
            lines.append(current)
        height = sum(draw.textbbox((0, 0), line, font=font)[3] - draw.textbbox((0, 0), line, font=font)[1] for line in lines) + max(0, len(lines)-1)*8
        if all(draw.textbbox((0,0), line, font=font)[2] <= max_width for line in lines) and height <= 360:
            return font, lines
    return load_font(min_size), [text]


def generated_art_palette(system: str):
    return {'gba': ((38, 26, 91), (36, 137, 209), (255, 208, 64)), 'snes': ((55, 43, 86), (126, 91, 191), (245,245,245)), 'nes': ((45,45,45), (188,30,45), (240,240,240)), 'genesis': ((18,18,28), (36,80,190), (240,40,40))}.get(system, ((20,20,30), (80,120,220), (245,245,245)))


def render_generated_art(game: dict, out: Path, size: tuple[int, int], kind: str):
    bg, accent, text_color = generated_art_palette(game['system'])
    w, h = size
    img = Image.new('RGB', size, bg)
    draw = ImageDraw.Draw(img)
    for i in range(0, max(w, h), 42):
        color = tuple(int(bg[j] + (accent[j] - bg[j]) * 0.35) for j in range(3))
        draw.line([(i, 0), (0, i)], fill=color, width=3)
        draw.line([(w - i, h), (w, h - i)], fill=color, width=2)
    margin = max(32, w // 18)
    draw.rounded_rectangle([margin, margin, w-margin, h-margin], radius=34, outline=accent, width=max(5, w//120))
    title = clean_game_title(game['appname']).upper()
    font, lines = fit_text(draw, title, w - margin*3, 88 if w > h else 72)
    total_h = sum(draw.textbbox((0,0), line, font=font)[3] for line in lines) + max(0, len(lines)-1)*10
    y = (h - total_h)//2
    for line in lines:
        bbox = draw.textbbox((0, 0), line, font=font)
        x = (w - (bbox[2]-bbox[0]))//2
        draw.text((x+4, y+4), line, font=font, fill=(0,0,0))
        draw.text((x, y), line, font=font, fill=text_color)
        y += (bbox[3]-bbox[1]) + 10
    small = load_font(30 if w > h else 24)
    footer = f"{game['system'].upper()} · RETROARCH"
    bbox = draw.textbbox((0, 0), footer, font=small)
    draw.text(((w-(bbox[2]-bbox[0]))//2, h-margin-44), footer, font=small, fill=text_color)
    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out)


def resize_cover(src: Path, out: Path, size: tuple[int, int]) -> None:
    im = Image.open(src).convert('RGB')
    canvas = Image.new('RGB', size, (12, 14, 22))
    bg = im.copy(); bg.thumbnail((size[0] * 2, size[1] * 2))
    scale = max(size[0] / bg.size[0], size[1] / bg.size[1])
    bg = bg.resize((max(1, int(bg.size[0] * scale)), max(1, int(bg.size[1] * scale))))
    canvas.paste(bg, ((size[0] - bg.size[0]) // 2, (size[1] - bg.size[1]) // 2))
    canvas = Image.blend(canvas, Image.new('RGB', size, (0, 0, 0)), 0.28)
    fg = im.copy(); fg.thumbnail((int(size[0] * 0.82), int(size[1] * 0.82)))
    canvas.paste(fg, ((size[0] - fg.size[0]) // 2, (size[1] - fg.size[1]) // 2))
    out.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(out)


def compose_provider_art(game: dict, art_dir: Path, provider: dict) -> None:
    title = clean_game_title(game['appname'])
    box = Path(provider.get('boxart') or '') if provider.get('boxart') else None
    banner = Path(provider.get('banner') or '') if provider.get('banner') else None
    if box and box.exists():
        if not (art_dir / 'grid.png').exists(): resize_cover(box, art_dir / 'grid.png', (600, 900))
        if not (art_dir / 'icon.png').exists(): resize_cover(box, art_dir / 'icon.png', (512, 512))
        if not (art_dir / 'landscape.png').exists(): resize_cover(box, art_dir / 'landscape.png', (920, 430))
    if banner and banner.exists() and not (art_dir / 'landscape.png').exists():
        im = Image.open(banner).convert('RGB'); im.thumbnail((920, 430))
        canvas = Image.new('RGB', (920, 430), (12, 14, 22)); canvas.paste(im, ((920-im.size[0])//2, (430-im.size[1])//2)); canvas.save(art_dir / 'landscape.png')
    if not (art_dir / 'hero.png').exists():
        base = Image.open(art_dir / 'landscape.png').convert('RGB') if (art_dir/'landscape.png').exists() else Image.open(art_dir/'grid.png').convert('RGB')
        hero = Image.new('RGB', (1920, 620), (12, 14, 22))
        bg = base.copy(); bg.thumbnail((3840, 1240)); scale = max(1920/bg.size[0], 620/bg.size[1]); bg = bg.resize((int(bg.size[0]*scale), int(bg.size[1]*scale)))
        hero.paste(bg, ((1920-bg.size[0])//2, (620-bg.size[1])//2)); hero = Image.blend(hero, Image.new('RGB', hero.size, (0,0,0)), 0.35)
        draw = ImageDraw.Draw(hero); font, lines = fit_text(draw, title.upper(), 1000, 88, 36)
        y = 230 - 48 * (len(lines)-1)
        for line in lines:
            draw.text((84, y+4), line, font=font, fill=(0,0,0)); draw.text((80, y), line, font=font, fill=(255,235,120)); y += 92
        draw.text((84, 520), f'{game["system"].upper()} · {infer_region(game["path"]).upper()}', font=load_font(34), fill=(240,240,240))
        hero.save(art_dir / 'hero.png')
    if not (art_dir / 'logo.png').exists():
        logo = Image.new('RGBA', (800, 310), (0,0,0,0)); d = ImageDraw.Draw(logo); font, lines = fit_text(d, title.upper(), 720, 76, 30)
        y = 105 - 38 * (len(lines)-1)
        for line in lines:
            bbox = d.textbbox((0,0), line, font=font); x=(800-(bbox[2]-bbox[0]))//2
            d.text((x+4,y+4), line, font=font, fill=(0,0,0,210)); d.text((x,y), line, font=font, fill=(255,235,120,255)); y += (bbox[3]-bbox[1]) + 8
        logo.save(art_dir / 'logo.png')


def resolve_steamgriddb_artwork(game: dict, env: dict[str, str], art_dir: Path) -> dict | None:
    key = env.get('STEAMGRIDDB_API_KEY') or env.get('STEAMGRIDDB')
    if not key:
        return None
    title = clean_game_title(game['appname'])
    headers = {'Authorization': 'Bearer ' + key, 'User-Agent': 'arch-game-sync/0.1'}
    try:
        search = http_json('https://www.steamgriddb.com/api/v2/search/autocomplete/' + urllib.parse.quote(title), headers=headers)
        rows = search.get('data') or []
        if not rows: return None
        gid = rows[0].get('id')
        provider = {'provider': 'steamgriddb', 'game_id': gid, 'title': rows[0].get('name'), 'assets': []}
        endpoints = [('grid', f'https://www.steamgriddb.com/api/v2/grids/game/{gid}?dimensions=600x900&types=static&nsfw=false&humor=false&epilepsy=false'), ('landscape', f'https://www.steamgriddb.com/api/v2/grids/game/{gid}?dimensions=920x430&types=static&nsfw=false&humor=false&epilepsy=false'), ('hero', f'https://www.steamgriddb.com/api/v2/heroes/game/{gid}?dimensions=1920x620&types=static&nsfw=false&humor=false&epilepsy=false'), ('logo', f'https://www.steamgriddb.com/api/v2/logos/game/{gid}?types=static&nsfw=false&humor=false&epilepsy=false'), ('icon', f'https://www.steamgriddb.com/api/v2/icons/game/{gid}?dimensions=512x512&types=static&nsfw=false&humor=false&epilepsy=false')]
        for kind, url in endpoints:
            try:
                data = http_json(url, headers=headers); assets = data.get('data') or []
                if assets and assets[0].get('url') and download_file(assets[0]['url'], art_dir / f'{kind}.png', headers={'User-Agent': 'arch-game-sync/0.1'}):
                    provider['assets'].append({'type': kind, 'source_id': assets[0].get('id'), 'path': str(art_dir / f'{kind}.png')})
            except Exception:
                continue
        return provider if provider['assets'] else None
    except Exception as exc:
        return {'provider': 'steamgriddb', 'error': type(exc).__name__}


def resolve_tgdb_artwork(game: dict, env: dict[str, str], art_dir: Path) -> dict | None:
    key = env.get('THEGAMESDB_API_KEY') or env.get('THEGAMESDB')
    platform = TGDB_PLATFORM_IDS.get(game['system'])
    if not key or not platform:
        return None
    title = clean_game_title(game['appname'])
    try:
        search_url = 'https://api.thegamesdb.net/v1.1/Games/ByGameName?' + urllib.parse.urlencode({'apikey': key, 'name': title, 'filter[platform]': platform})
        games = ((http_json(search_url).get('data') or {}).get('games') or [])
        if not games: return None
        chosen = games[0]; gid = str(chosen.get('id'))
        images_url = 'https://api.thegamesdb.net/v1/Games/Images?' + urllib.parse.urlencode({'apikey': key, 'games_id': gid})
        image_data = http_json(images_url).get('data') or {}
        base = ((image_data.get('base_url') or {}).get('original') or '').rstrip('/') + '/'
        provider = {'provider': 'thegamesdb', 'game_id': gid, 'title': chosen.get('game_title'), 'platform': chosen.get('platform'), 'region': infer_region(game['path']), 'assets': []}
        for row in (image_data.get('images') or {}).get(gid, []) or []:
            typ, side, filename = row.get('type'), row.get('side'), row.get('filename')
            if not filename: continue
            if typ == 'boxart' and side == 'front' and 'boxart' not in provider:
                out = art_dir / 'raw/thegamesdb-boxart-front.jpg'
                if download_file(base + filename, out, headers={'User-Agent': 'Mozilla/5.0 arch-game-sync'}):
                    provider['boxart'] = str(out); provider['assets'].append({'type': typ, 'side': side, 'path': str(out)})
            elif typ == 'banner' and 'banner' not in provider:
                out = art_dir / 'raw/thegamesdb-banner.jpg'
                if download_file(base + filename, out, headers={'User-Agent': 'Mozilla/5.0 arch-game-sync'}):
                    provider['banner'] = str(out); provider['assets'].append({'type': typ, 'path': str(out)})
        if not provider['assets']: return None
        compose_provider_art(game, art_dir, provider)
        return provider
    except Exception as exc:
        return {'provider': 'thegamesdb', 'error': type(exc).__name__}


def resolve_screenscraper_artwork(game: dict, env: dict[str, str], art_dir: Path) -> dict | None:
    required = ['SCREENSCRAPER_API_KEY']
    if not all(env.get(k) for k in required):
        return None
    return {'provider': 'screenscraper', 'status': 'api-key-present-not-yet-implemented'}


def game_artwork_dir(game: dict) -> Path:
    return ARTWORK_ROOT / game['system'] / slugify(clean_game_title(game['appname']))


def resolve_provider_artwork(game: dict, art_dir: Path) -> dict | None:
    env = read_provider_env()
    attempts = []
    required = ['grid.png', 'landscape.png', 'hero.png', 'logo.png', 'icon.png']
    for resolver in [resolve_steamgriddb_artwork, resolve_tgdb_artwork, resolve_screenscraper_artwork]:
        result = resolver(game, env, art_dir)
        if result: attempts.append(dict(result))
        elif result is not None: attempts.append(dict(result))
        if all((art_dir / name).exists() and (art_dir / name).stat().st_size > 0 for name in required) and attempts:
            providers, assets = [], []
            for attempt in attempts:
                if attempt.get('provider') and attempt.get('provider') not in providers: providers.append(attempt['provider'])
                assets.extend(attempt.get('assets') or [])
            return {'provider': 'provider-merge', 'providers': providers, 'attempts': [dict(a) for a in attempts], 'assets': assets}
    return {'provider': 'provider-partial', 'attempts': [dict(a) for a in attempts], 'assets': []} if attempts else None


def ensure_cached_artwork(game: dict) -> dict:
    art_dir = game_artwork_dir(game); art_dir.mkdir(parents=True, exist_ok=True)
    specs = {'grid': ('grid.png', (600, 900), 'portrait-grid'), 'hero': ('hero.png', (1920, 620), 'hero'), 'landscape': ('landscape.png', (920, 430), 'landscape-grid'), 'logo': ('logo.png', (800, 310), 'logo'), 'icon': ('icon.png', (512, 512), 'icon')}
    existing_files = {key: str(art_dir / filename) for key, (filename, size, kind) in specs.items()}
    metadata_path = art_dir / 'metadata.json'
    if metadata_path.exists() and all(Path(p).exists() and Path(p).stat().st_size > 0 for p in existing_files.values()):
        try:
            metadata = json.loads(metadata_path.read_text()); metadata['files'] = existing_files; metadata['source'] = metadata.get('source', 'cache'); return metadata
        except Exception:
            pass
    provider = resolve_provider_artwork(game, art_dir)
    generated, files = [], {}
    for key, (filename, size, kind) in specs.items():
        out = art_dir / filename
        if not out.exists() or out.stat().st_size == 0:
            render_generated_art(game, out, size, kind); generated.append(key)
        files[key] = str(out)
    source = provider.get('provider') if provider and provider.get('provider') else ('generated-deterministic-fallback' if generated else 'cache')
    metadata = {'schema': 'arch_game_sync.artwork_cache.v2', 'appname': game['appname'], 'system': game['system'], 'region': infer_region(game['path']), 'rom': str(game['path']), 'resolver_key': f"{slugify(clean_game_title(game['appname']))}:{game['system']}:{infer_region(game['path'])}", 'source': source, 'provider': provider, 'generated': generated, 'files': files, 'updated_unix': int(time.time())}
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    return metadata


def install_steam_grid_art(game: dict, entry: dict, shortcuts_path: Path) -> dict:
    appid = appid_unsigned(int(entry['appid']))
    cache = ensure_cached_artwork(game)
    grid = steam_grid_dir(shortcuts_path)
    mapping = {f'{appid}p.png': cache['files']['grid'], f'{appid}.png': cache['files']['landscape'], f'{appid}_hero.png': cache['files']['hero'], f'{appid}_logo.png': cache['files']['logo'], f'{appid}_icon.png': cache['files']['icon']}
    installed = []
    for filename, src in mapping.items():
        dst = grid / filename; shutil.copy2(src, dst); installed.append(str(dst))
    try:
        info = pwd.getpwnam(OWNER_USER)
        for dst in grid.glob(f'{appid}*'):
            os.chown(dst, info.pw_uid, info.pw_gid); os.chmod(dst, 0o644)
        os.chown(grid, info.pw_uid, info.pw_gid)
    except KeyError:
        pass
    return {'appname': game['appname'], 'system': game['system'], 'rom': str(game['path']), 'appid': appid, 'appid_signed': int(entry['appid']), 'artwork_cache': cache, 'steam_grid_files': installed}


def missing_bios_for(system: str) -> list[str]:
    req = BIOS_REQUIREMENTS.get(system)
    if not req:
        return []
    return [str(BIOS_ROOT / rel) for rel in req['paths'] if not (BIOS_ROOT / rel).exists()]


def scan_games(runners):
    games, blocked = [], []
    for system, cfg in runners['systems'].items():
        if cfg.get('runner') not in {'retroarch', 'dosbox'}:
            continue
        rom_dir = Path(cfg['rom_dir']); extensions = {e.lower() for e in cfg.get('extensions', [])}
        if not rom_dir.exists():
            continue
        for path in sorted(p for p in rom_dir.iterdir() if p.is_file() and p.suffix.lower() in extensions):
            missing = missing_bios_for(system)
            if missing:
                blocked.append({'system': system, 'path': str(path), 'reason': 'missing-user-bios', 'missing_paths': missing, 'policy': BIOS_REQUIREMENTS[system]['policy']})
                continue
            exe = '/usr/bin/retroarch' if cfg['runner'] == 'retroarch' else '/usr/bin/dosbox'
            launch = f'-L {cfg["core"]} "{path}"' if cfg['runner'] == 'retroarch' else f'"{path}"'
            games.append({'system': system, 'path': path, 'appname': title_from_path(path, system), 'exe': exe, 'launchoptions': launch, 'tags': cfg.get('tags', [system, 'syncr'])})
    return games, blocked


def merge_shortcuts(data, games):
    shortcuts = data.setdefault('shortcuts', {})
    next_idx = max([int(k) for k in shortcuts.keys() if str(k).isdigit()] or [-1]) + 1
    changed, written = False, []
    for game in games:
        key = next((k for k, v in shortcuts.items() if v.get('AppName') == game['appname'] or v.get('appname') == game['appname']), None)
        if key is None:
            key = str(next_idx); next_idx += 1
        exe = f'"{game["exe"]}"'
        entry = {'appid': appid_signed(game['exe'], game['appname']), 'AppName': game['appname'], 'appname': game['appname'], 'Exe': exe, 'exe': exe, 'StartDir': f'"{str(Path(game["exe"]).parent)}"', 'startdir': f'"{str(Path(game["exe"]).parent)}"', 'icon': '', 'ShortcutPath': '', 'LaunchOptions': game['launchoptions'], 'launchoptions': game['launchoptions'], 'IsHidden': 0, 'AllowDesktopConfig': 1, 'AllowOverlay': 1, 'OpenVR': 0, 'Devkit': 0, 'DevkitGameID': '', 'LastPlayTime': 0, 'FlatpakAppID': '', 'tags': {str(i): tag for i, tag in enumerate(game['tags'])}}
        if shortcuts.get(key) != entry:
            shortcuts[key] = entry; changed = True
        written.append({'key': key, 'entry': entry, 'game': game})
    return changed, written


def _sync_main():
    parser = argparse.ArgumentParser(description='Sync Arch gaming-console folders into Steam shortcuts and Steam grid artwork')
    args = parser.parse_args()
    RECEIPT_DIR.mkdir(parents=True, exist_ok=True)
    runners = json.loads(RUNNERS_PATH.read_text())
    games, blocked_payloads = scan_games(runners)
    shortcuts_path = find_shortcuts_file()
    data = read_shortcuts(shortcuts_path)
    changed, written = merge_shortcuts(data, games)
    if changed:
        write_shortcuts(shortcuts_path, data)
    artwork = [install_steam_grid_art(item['game'], item['entry'], shortcuts_path) for item in written]
    readback = read_shortcuts(shortcuts_path)
    receipt = {'ok': True, 'schema': 'arch_game_sync.local.receipt.v2', 'games': [g['appname'] for g in games], 'game_count': len(games), 'blocked_payloads': blocked_payloads, 'bios_requirements': BIOS_REQUIREMENTS, 'shortcuts_path': str(shortcuts_path), 'readback_count': len(readback.get('shortcuts', {})), 'changed': changed, 'artwork': artwork, 'restart_recommended': 'steam', 'payload_boundary': 'runtime-game-files-artwork-cache-bios-firmware-keys-and-secrets-not-source', 'provider_env_path': str(PROVIDER_ENV)}
    path = RECEIPT_DIR / f'arch-game-sync-{int(time.time())}.json'
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps({**receipt, 'receipt_path': str(path)}, sort_keys=True))


def main(argv=None):
    import sys
    previous = sys.argv
    try:
        sys.argv = [previous[0], *(argv or [])]
        _sync_main()
        return 0
    finally:
        sys.argv = previous


if __name__ == "__main__":
    raise SystemExit(main())
