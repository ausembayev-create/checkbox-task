#!/usr/bin/env node
// ══════════════════════════════════════════
// CHECKBOX TASK — DISK TOZALASH SKRIPTI
// Ishlatish: node cleanup.js
// ══════════════════════════════════════════
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_FILE   = process.env.DATA_PATH   || path.join(__dirname, 'data.json');
const UPLOADS_DIR = process.env.UPLOADS_PATH || path.join(__dirname, 'uploads');

// R2 sozlamalari
const R2_ACCESS_KEY = process.env.R2_ACCESS_KEY_ID || '';
const R2_SECRET_KEY = process.env.R2_SECRET_ACCESS_KEY || '';
const R2_BUCKET     = process.env.R2_BUCKET_NAME || 'checkbox-task-uploads';
const R2_ENDPOINT   = (process.env.R2_ENDPOINT || '').replace(/\/+$/, '');
const USE_R2        = !!(R2_ACCESS_KEY && R2_SECRET_KEY && R2_ENDPOINT);

function awsSign(method, filename) {
  const url = `${R2_ENDPOINT}/${R2_BUCKET}/${filename}`;
  const host = new URL(url).host;
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:\-]|\.\d{3}/g,'').slice(0,16)+'Z';
  const dateStamp = amzDate.slice(0,8);
  const payloadHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const hdrs = {'host':host,'x-amz-date':amzDate,'x-amz-content-sha256':payloadHash};
  const shKeys = Object.keys(hdrs).sort();
  const signedHeaders = shKeys.join(';');
  const canonicalHeaders = shKeys.map(k=>`${k}:${hdrs[k]}`).join('\n')+'\n';
  const cr = [method,`/${R2_BUCKET}/${filename}`,'',canonicalHeaders,signedHeaders,payloadHash].join('\n');
  const scope = `${dateStamp}/auto/s3/aws4_request`;
  const sts = `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n`+crypto.createHash('sha256').update(cr).digest('hex');
  const hmac=(k,d)=>crypto.createHmac('sha256',k).update(d).digest();
  const sk=hmac(hmac(hmac(hmac('AWS4'+R2_SECRET_KEY,dateStamp),'auto'),'s3'),'aws4_request');
  const sig=crypto.createHmac('sha256',sk).update(sts).digest('hex');
  hdrs['Authorization']=`AWS4-HMAC-SHA256 Credential=${R2_ACCESS_KEY}/${scope}, SignedHeaders=${signedHeaders}, Signature=${sig}`;
  return {url, headers:hdrs};
}

async function r2Delete(filename) {
  if (!filename || !USE_R2) return false;
  try {
    const {url, headers} = awsSign('DELETE', filename);
    await fetch(url, {method:'DELETE', headers});
    return true;
  } catch(e) { return false; }
}

async function main() {
  console.log('\n🔍 CHECKBOX TASK — DISK TOZALASH SKRIPTI');
  console.log('='.repeat(50));

  if (!fs.existsSync(DATA_FILE)) {
    console.log('❌ data.json topilmadi:', DATA_FILE); process.exit(1);
  }

  const db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  const tasks    = db.tasks    || [];
  const files    = db.files    || [];
  const comments = db.comments || [];
  const archive  = db.archive  || [];
  const users    = db.users    || [];

  console.log(`\n📊 MAVJUD MA'LUMOTLAR:`);
  console.log(`   Foydalanuvchilar: ${users.length}`);
  console.log(`   Topshiriqlar:     ${tasks.length}`);
  console.log(`   Fayllar (DB):     ${files.length}`);
  console.log(`   Izohlar:          ${comments.length}`);
  console.log(`   Arxivlar:         ${archive.length}`);

  // 1. Aktiv task ID larini to'playmiz
  const activeTaskIds = new Set(tasks.map(t => t.id));

  // 2. Yetim fayllarni topish (task yo'q)
  const orphanFiles = files.filter(f => f.ref_id && !activeTaskIds.has(f.ref_id));
  const activeFiles = files.filter(f => !f.ref_id || activeTaskIds.has(f.ref_id));

  console.log(`\n🗂️  FAYLLAR TAHLILI:`);
  console.log(`   Aktiv topshiriqlarga bog'liq: ${activeFiles.length}`);
  console.log(`   Yetim (o'chirilgan task):     ${orphanFiles.length}`);

  if (orphanFiles.length === 0) {
    console.log('\n✅ Yetim fayl yo\'q — hamma narsa tartibda!');
  } else {
    console.log('\n🗑️  YETIM FAYLLARNI O\'CHIRISH:');
    let deletedR2 = 0, deletedLocal = 0, failedCount = 0;

    for (const f of orphanFiles) {
      process.stdout.write(`   ${f.name || f.filename} ... `);
      let deleted = false;

      // R2 dan o'chirish
      if (USE_R2 && f.url && f.url.startsWith('http')) {
        deleted = await r2Delete(f.filename);
        if (deleted) { deletedR2++; console.log('✅ R2 dan o\'chirildi'); }
        else { console.log('⚠️  R2 xato'); failedCount++; }
      }
      // Local dan o'chirish
      else if (f.filename) {
        const fp = path.join(UPLOADS_DIR, f.filename);
        if (fs.existsSync(fp)) {
          try { fs.unlinkSync(fp); deletedLocal++; deleted = true; console.log('✅ Diskdan o\'chirildi'); }
          catch(e) { console.log('❌ Xato:', e.message); failedCount++; }
        } else {
          console.log('⚠️  Allaqachon yo\'q');
          deleted = true;
        }
      } else {
        console.log('⚠️  Fayl nomi yo\'q');
        deleted = true;
      }
    }

    // DB dan yetim fayllarni o'chirish
    db.files = activeFiles;
    console.log(`\n   R2 dan o\'chirildi:    ${deletedR2}`);
    console.log(`   Diskdan o\'chirildi:   ${deletedLocal}`);
    console.log(`   Xatolar:              ${failedCount}`);
  }

  // 3. Yetim izohlarni tozalash
  const orphanComments = comments.filter(c => !activeTaskIds.has(c.task_id));
  if (orphanComments.length > 0) {
    db.comments = comments.filter(c => activeTaskIds.has(c.task_id));
    console.log(`\n🗑️  Yetim izohlar o\'chirildi: ${orphanComments.length}`);
  }

  // 4. Local uploads papkasidagi yetim fayllarni topish
  console.log('\n📁 LOCAL UPLOADS PAPKASI:');
  if (fs.existsSync(UPLOADS_DIR)) {
    const localFiles = fs.readdirSync(UPLOADS_DIR).filter(f => f !== '.gitkeep');
    const dbFilenames = new Set((db.files || []).map(f => f.filename).filter(Boolean));
    const orphanLocal = localFiles.filter(f => !dbFilenames.has(f));

    console.log(`   Jami local fayllar:  ${localFiles.length}`);
    console.log(`   DB da ro'yxatdagi:   ${dbFilenames.size}`);
    console.log(`   Yetim (DB da yo'q):  ${orphanLocal.length}`);

    if (orphanLocal.length > 0) {
      let localFreed = 0;
      for (const fname of orphanLocal) {
        const fp = path.join(UPLOADS_DIR, fname);
        try {
          const size = fs.statSync(fp).size;
          fs.unlinkSync(fp);
          localFreed += size;
        } catch {}
      }
      console.log(`   Bo'shagan joy: ${(localFreed/1024/1024).toFixed(2)} MB`);
    }
  } else {
    console.log('   Uploads papkasi topilmadi');
  }

  // 5. Saqlash
  if (orphanFiles.length > 0 || orphanComments.length > 0) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
    console.log('\n💾 data.json yangilandi');
  }

  console.log('\n' + '='.repeat(50));
  console.log('✅ TOZALASH TUGADI!');
  console.log('');
}

main().catch(e => { console.error('Xato:', e); process.exit(1); });
