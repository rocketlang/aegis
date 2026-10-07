/**
 * Posture Report Card routes — JSON + PDF + WhatsApp delivery.
 * @rule:P2-003 Report Card distribution channels
 * @rule:CA-001 Large output escape
 * @rule:CA-004 _meta on every resolver
 */

import { execSync } from 'child_process';
import { readFileSync, unlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import type { FastifyInstance } from 'fastify';

import { getVessel } from '../store/vessel.js';

import { assembleReportCard, buildReportHTML, buildWhatsAppSummary, sendWhatsApp } from './card.js';
import type { ReportCard } from './card.js';

export async function registerReportRoutes(app: FastifyInstance): Promise<void> {
  // GET /api/v1/report/:vesselId — JSON Report Card
  app.get<{ Params: { vesselId: string } }>('/api/v1/report/:vesselId', async (request, reply) => {
    const _start = Date.now();
    const card = await assembleReportCard(request.params.vesselId);

    // @rule:CA-001 overflow already handled inside assembleReportCard
    return reply.send({
      ...card,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    });
  });

  // GET /api/v1/report/:vesselId/pdf — PDF Report Card via wkhtmltopdf
  app.get<{ Params: { vesselId: string } }>(
    '/api/v1/report/:vesselId/pdf',
    async (request, reply) => {
      const card = await assembleReportCard(request.params.vesselId);

      if ('overflow_granthx_ref' in card) {
        return reply.status(302).redirect(card.overflow_granthx_ref);
      }

      const html = buildReportHTML(card as ReportCard);
      const htmlPath = join(tmpdir(), `varuna-${request.params.vesselId}-${Date.now()}.html`);
      const pdfPath = htmlPath.replace('.html', '.pdf');

      try {
        writeFileSync(htmlPath, html, 'utf8');
        execSync(`wkhtmltopdf --quiet --page-size A4 "${htmlPath}" "${pdfPath}"`, {
          timeout: 30000,
        });
        const pdfBuf = readFileSync(pdfPath);
        unlinkSync(htmlPath);
        unlinkSync(pdfPath);
        return reply
          .header('Content-Type', 'application/pdf')
          .header(
            'Content-Disposition',
            `attachment; filename="varuna-${request.params.vesselId}.pdf"`
          )
          .send(pdfBuf);
      } catch (err) {
        try {
          unlinkSync(htmlPath);
        } catch (_e) {
          /* best-effort cleanup */
        }
        try {
          unlinkSync(pdfPath);
        } catch (_e) {
          /* best-effort cleanup */
        }
        app.log.warn({ err }, 'PDF generation failed — returning HTML');
        return reply.header('Content-Type', 'text/html').send(html);
      }
    }
  );

  // POST /api/v1/report/:vesselId/whatsapp — WhatsApp delivery via AnkrClaw
  app.post<{
    Params: { vesselId: string };
    Body: { to: string };
  }>('/api/v1/report/:vesselId/whatsapp', async (request, reply) => {
    const _start = Date.now();
    const { to } = request.body;
    if (!to) return reply.status(400).send({ error: 'to is required (WhatsApp number)' });

    const card = await assembleReportCard(request.params.vesselId);
    if ('overflow_granthx_ref' in card) {
      return {
        delivered: false,
        reason: 'overflow',
        overflow_granthx_ref: card.overflow_granthx_ref,
      };
    }

    const text = buildWhatsAppSummary(card as ReportCard);
    const delivered = await sendWhatsApp(to, text);

    return {
      delivered,
      vessel_id: request.params.vesselId,
      to,
      message_length: text.length,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // GET /api/v1/report/:vesselId/history — score history (append-only)
  app.get<{ Params: { vesselId: string }; Querystring: { limit?: string } }>(
    '/api/v1/report/:vesselId/history',
    async (request) => {
      const _start = Date.now();
      const vessel = getVessel(request.params.vesselId);
      const limit = parseInt(request.query.limit ?? '50');
      const history = [...vessel.score_history].reverse().slice(0, limit);

      return {
        vessel_id: request.params.vesselId,
        total_checkpoints: vessel.score_history.length,
        returned: history.length,
        history,
        _meta: {
          computed_at: new Date().toISOString(),
          duration_ms: Date.now() - _start,
          trust_mask_applied: 1,
        },
      };
    }
  );

  app.log.info('Report routes registered: JSON + PDF + WhatsApp + history (VARUNA-P2-003, P2-005)');
}
