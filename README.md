# Streamer

[เปิดเว็บควบคุม streamer+](https://streamer-install-api.babybadx7.workers.dev/)

ลูกค้ากรอก License key บนเว็บ สร้างคำสั่งติดตั้ง แล้วนำไปวางใน PowerShell และยอมรับ UAC โปรแกรมรุ่นใหม่จะตรวจ key อัตโนมัติ เมื่อโปรแกรมออนไลน์สามารถปรับค่าจากเว็บแล้วกดบันทึกได้

## Control center

Web frontend and Cloudflare Worker API are in `control-center/`. See [คู่มือ](control-center/WEB-GUIDE-TH.md).

Run `npm test` in that directory. Deployment requires Cloudflare Workers, private R2, D1 and separately configured secrets `KEYAUTH_SELLER_KEY`, `ADMIN_TOKEN`, `LICENSE_ENCRYPTION_KEY`. Apply both SQL schema files before a fresh deployment. No credentials or generated customer commands are included here.

The latest executable is distributed through the authenticated installer from private R2. The source for the Windows application remains in the local project; this folder contains the web service. Older root PowerShell scripts and GitHub releases are legacy distribution and do not provide the new web-control workflow.
