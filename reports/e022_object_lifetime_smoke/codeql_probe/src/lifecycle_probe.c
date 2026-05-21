struct zcrypt_card { int ref; };
struct zcrypt_queue { int ref; struct zcrypt_card *card; };
struct rxe_qp { void *sq_queue; void *rq_queue; void *pd; void *rcq; void *scq; void *srq; };
struct amdtee_session { int refcount; };
struct mutex { int locked; };
struct sctp_endpoint { int refcnt; void *rcu; void *sk; };
struct ip_mc_list { int refcnt; void *timer; int tm_running; };

extern int jiffies;
extern struct mutex session_list_mutex;

void zcrypt_card_put(struct zcrypt_card *card);
void zcrypt_queue_put(struct zcrypt_queue *queue);
void zcrypt_card_get(struct zcrypt_card *card);
void zcrypt_queue_get(struct zcrypt_queue *queue);
void rxe_queue_cleanup(void *queue);
void rxe_drop_ref(void *object);
void kref_put(int *refcount, void (*release)(struct amdtee_session *session));
void kref_put_mutex(int *refcount, void (*release)(struct amdtee_session *session), struct mutex *lock);
void destroy_session(struct amdtee_session *session);
void sock_put(void *sk);
void kfree(void *ptr);
void call_rcu(void *head, void (*func)(struct sctp_endpoint *endpoint));
void sctp_endpoint_destroy_rcu(struct sctp_endpoint *endpoint);
void refcount_inc(int *refcount);
int refcount_inc_not_zero(int *refcount);
int mod_timer(void *timer, int expires);
void ip_ma_put(struct ip_mc_list *im);

void vs_smoke_C0001_fixed_zcrypt_card_unregister(struct zcrypt_card *zc)
{
	zcrypt_card_put(zc);
}

void vs_smoke_C0002_fixed_zcrypt_queue_unregister(struct zcrypt_queue *zq)
{
	zcrypt_card_put(zq->card);
	zcrypt_queue_put(zq);
}

void vs_smoke_C0003_fixed_rxe_qp_from_init(struct rxe_qp *qp)
{
	rxe_queue_cleanup(qp->sq_queue);
	qp->sq_queue = 0;
	rxe_queue_cleanup(qp->rq_queue);
	qp->rq_queue = 0;
	qp->pd = 0;
	qp->rcq = 0;
	qp->scq = 0;
	qp->srq = 0;
}

void vs_smoke_C0004_related_rxe_elem_release(void *obj)
{
	kfree(obj);
}

void vs_smoke_C0005_vulnerable_amdtee_close_session(struct amdtee_session *sess)
{
	kref_put(&sess->refcount, destroy_session);
}

void vs_smoke_C0005_fixed_amdtee_close_session(struct amdtee_session *sess)
{
	kref_put_mutex(&sess->refcount, destroy_session, &session_list_mutex);
}

void vs_smoke_C0006_vulnerable_amdtee_open_session(struct amdtee_session *sess)
{
	kref_put(&sess->refcount, destroy_session);
}

void vs_smoke_C0006_fixed_amdtee_open_session(struct amdtee_session *sess)
{
	kref_put_mutex(&sess->refcount, destroy_session, &session_list_mutex);
}

void vs_smoke_C0007_fixed_sctp_sock_dump(struct sctp_endpoint *ep)
{
	if (refcount_inc_not_zero(&ep->refcnt))
		sock_put(ep->sk);
}

void vs_smoke_C0008_vulnerable_sctp_endpoint_destroy(struct sctp_endpoint *ep)
{
	sock_put(ep->sk);
	kfree(ep);
}

void vs_smoke_C0008_fixed_sctp_endpoint_destroy(struct sctp_endpoint *ep)
{
	call_rcu(&ep->rcu, sctp_endpoint_destroy_rcu);
}

void vs_smoke_C0009_vulnerable_igmp_start_timer(struct ip_mc_list *im, int tv)
{
	im->tm_running = 1;
	if (!mod_timer(&im->timer, jiffies + tv + 2))
		refcount_inc(&im->refcnt);
}

void vs_smoke_C0009_fixed_igmp_start_timer(struct ip_mc_list *im, int tv)
{
	im->tm_running = 1;
	if (refcount_inc_not_zero(&im->refcnt)) {
		if (mod_timer(&im->timer, jiffies + tv + 2))
			ip_ma_put(im);
	}
}
