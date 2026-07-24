# Part of Odoo. See LICENSE file for full copyright and licensing details.
import json

from odoo.tests import HttpCase, tagged


@tagged('-at_install', 'post_install')
class TestReadSubscriptionDataSecurity(HttpCase):
    """Regression tests for CVE-2024-36259.

    /mail/read_subscription_data must validate access on (thread_model,
    thread_id) before resolving the follower, and must reject a follower_id
    that does not belong to the given thread, instead of trusting a bare
    follower_id to reverse-lookup an arbitrary res_model/res_id pair (which
    turned the endpoint into a yes/no access oracle).
    """

    def setUp(self):
        super().setUp()
        self.low_user = self.env['res.users'].create({
            'name': 'CVE Test LowPriv',
            'login': 'cve_test_lowpriv@example.com',
            'email': 'cve_test_lowpriv@example.com',
            'password': 'cve_test_12345',
            'groups_id': [(6, 0, [self.env.ref('base.group_user').id])],
        })
        self.confidential_doc = self.env['hr.employee'].create({'name': 'CVE test confidential employee'})
        self.confidential_doc.message_subscribe(partner_ids=[self.env.user.partner_id.id])
        self.confidential_follower = self.env['mail.followers'].sudo().search([
            ('res_model', '=', 'hr.employee'),
            ('res_id', '=', self.confidential_doc.id),
        ], limit=1)
        self.shared_doc = self.env['res.partner'].create({'name': 'CVE test shared doc'})
        self.shared_doc.message_subscribe(partner_ids=[self.env.user.partner_id.id])
        self.shared_follower = self.env['mail.followers'].sudo().search([
            ('res_model', '=', 'res.partner'),
            ('res_id', '=', self.shared_doc.id),
        ], limit=1)

    def _call_read_subscription_data(self, **kwargs):
        return self.url_open(
            '/mail/read_subscription_data',
            data=json.dumps({'jsonrpc': '2.0', 'method': 'call', 'params': kwargs}),
            headers={'Content-Type': 'application/json'},
        ).json()

    def test_cannot_use_arbitrary_follower_id_as_oracle(self):
        """A user without access to the underlying document must not be able
        to learn anything about it via a guessed follower_id, even when
        supplying a document they DO have access to."""
        self.authenticate('cve_test_lowpriv@example.com', 'cve_test_12345')

        # 1) directly targeting the confidential document: blocked at the
        #    document access check, before the follower is ever touched.
        res = self._call_read_subscription_data(
            follower_id=self.confidential_follower.id,
            thread_model='hr.employee',
            thread_id=self.confidential_doc.id,
        )
        self.assertIn('error', res, "low-priv user should not access the confidential document's subscription data")

        # 2) reusing the real (guessed) follower_id of the confidential doc,
        #    but lying about thread_model/thread_id with a document the
        #    attacker DOES have access to: must be rejected as a mismatch,
        #    not leak the confidential document's subtypes.
        res = self._call_read_subscription_data(
            follower_id=self.confidential_follower.id,
            thread_model='res.partner',
            thread_id=self.shared_doc.id,
        )
        self.assertIn('error', res, "follower_id/thread_model/thread_id mismatch must be rejected")
        self.assertEqual(res['error']['data']['name'], 'werkzeug.exceptions.NotFound')

        # 3) a nonexistent follower_id against an accessible document must
        #    produce the exact same error as (2): no distinguishable oracle
        #    between "wrong document" and "does not exist".
        res_missing = self._call_read_subscription_data(
            follower_id=999999999,
            thread_model='res.partner',
            thread_id=self.shared_doc.id,
        )
        self.assertEqual(res['error']['data']['name'], res_missing['error']['data']['name'])

    def test_legit_cross_user_follower_edit_still_works(self):
        """A user with access to a shared document must still be able to
        fetch subtype data for ANOTHER user's follower entry on that same
        document (e.g. to manage their notification subtypes from the
        chatter's follower list) -- this must not regress."""
        self.authenticate('cve_test_lowpriv@example.com', 'cve_test_12345')
        res = self._call_read_subscription_data(
            follower_id=self.shared_follower.id,
            thread_model='res.partner',
            thread_id=self.shared_doc.id,
        )
        self.assertNotIn('error', res, f"legitimate cross-user follower edit should succeed, got: {res}")
        self.assertIsInstance(res['result'], list)
        self.assertTrue(res['result'])
