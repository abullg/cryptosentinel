import { NextRequest, NextResponse } from 'next/server';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export async function GET(req: NextRequest) {
  const action = req.nextUrl.searchParams.get('action') || 'status';

  try {
    switch (action) {
      case 'status': {
        const { stdout: pm2List } = await execAsync('pm2 list 2>&1 | head -10');
        const { stdout: dockerPs } = await execAsync('docker ps --format "table {{.Names}}\\t{{.Status}}\\t{{.Ports}}" 2>&1 | head -10');
        const { stdout: disk } = await execAsync('df -h / 2>&1 | tail -1');
        const { stdout: mem } = await execAsync('free -m 2>&1 | grep Mem');
        return NextResponse.json({ pm2: pm2List, docker: dockerPs, disk, mem });
      }
      case 'logs': {
        const lines = req.nextUrl.searchParams.get('lines') || '50';
        const { stdout } = await execAsync(`pm2 logs cryptosentinel --lines ${lines} --nostream 2>&1 | tail -${lines}`);
        return NextResponse.json({ logs: stdout });
      }
      case 'db-count': {
        const { execSync } = require('child_process');
        const dbFile = '/data/cryptosentinel.db';
        const count = execSync(`sqlite3 ${dbFile} "SELECT COUNT(*) FROM Vulnerability;"`).toString().trim();
        const jobs = execSync(`sqlite3 ${dbFile} "SELECT COUNT(*) FROM AnalysisJob;"`).toString().trim();
        return NextResponse.json({ vulnerabilities: parseInt(count), jobs: parseInt(jobs) });
      }
      default:
        return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
    }
  } catch (e: any) {
    return NextResponse.json({ error: String(e).slice(0, 300) }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const action = body.action;

  try {
    switch (action) {
      case 'gt-start': {
        const { stdout } = await execAsync('cd /opt/cryptosentinel/tests/gt && docker compose up -d 2>&1 | tail -5');
        return NextResponse.json({ result: stdout });
      }
      case 'gt-stop': {
        const { stdout } = await execAsync('cd /opt/cryptosentinel/tests/gt && docker compose stop 2>&1 | tail -5');
        return NextResponse.json({ result: stdout });
      }
      case 'gt-restart': {
        const { stdout } = await execAsync('cd /opt/cryptosentinel/tests/gt && docker compose restart 2>&1 | tail -5');
        return NextResponse.json({ result: stdout });
      }
      case 'pm2-restart': {
        const { stdout } = await execAsync('pm2 restart cryptosentinel --update-env 2>&1 | tail -3');
        return NextResponse.json({ result: stdout });
      }
      case 'clear-db': {
        const { execSync } = require('child_process');
        const dbFile = '/data/cryptosentinel.db';
        execSync(`sqlite3 ${dbFile} "DELETE FROM Vulnerability; DELETE FROM AnalysisJob;"`);
        return NextResponse.json({ result: 'DB cleared' });
      }
      case 'flush-logs': {
        const { stdout } = await execAsync('pm2 flush cryptosentinel 2>&1 | tail -2');
        return NextResponse.json({ result: stdout });
      }
      case 'git-pull': {
        const { stdout } = await execAsync('cd /opt/cryptosentinel && git pull --ff-only 2>&1 | tail -3');
        return NextResponse.json({ result: stdout });
      }
      default:
        return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
    }
  } catch (e: any) {
    return NextResponse.json({ error: String(e).slice(0, 300) }, { status: 500 });
  }
}
