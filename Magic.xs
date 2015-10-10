/* This file is part of the Variable::Magic Perl module.
 * See http://search.cpan.org/dist/Variable-Magic/ */

#include <stdarg.h> /* <va_list>, va_{start,arg,end}, ... */

#include <stdio.h>  /* sprintf() */

#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define __PACKAGE__ "Variable::Magic"

#undef VOID2
#ifdef __cplusplus
# define VOID2(T, P) static_cast<T>(P)
#else
# define VOID2(T, P) (P)
#endif

#ifndef VMG_PERL_PATCHLEVEL
# ifdef PERL_PATCHNUM
#  define VMG_PERL_PATCHLEVEL PERL_PATCHNUM
# else
#  define VMG_PERL_PATCHLEVEL 0
# endif
#endif

#define VMG_HAS_PERL(R, V, S) (PERL_REVISION > (R) || (PERL_REVISION == (R) && (PERL_VERSION > (V) || (PERL_VERSION == (V) && (PERL_SUBVERSION >= (S))))))

#define VMG_HAS_PERL_BRANCH(R, V, S) (PERL_REVISION == (R) && PERL_VERSION == (V) && PERL_SUBVERSION >= (S))

#define VMG_HAS_PERL_MAINT(R, V, S, P) (PERL_REVISION == (R) && PERL_VERSION == (V) && (VMG_PERL_PATCHLEVEL >= (P) || (!VMG_PERL_PATCHLEVEL && PERL_SUBVERSION >= (S))))

/* --- Threads and multiplicity -------------------------------------------- */

#ifndef NOOP
# define NOOP
#endif

#ifndef dNOOP
# define dNOOP
#endif

/* Safe unless stated otherwise in Makefile.PL */
#ifndef VMG_FORKSAFE
# define VMG_FORKSAFE 1
#endif

#ifndef VMG_MULTIPLICITY
# if defined(MULTIPLICITY) || defined(PERL_IMPLICIT_CONTEXT)
#  define VMG_MULTIPLICITY 1
# else
#  define VMG_MULTIPLICITY 0
# endif
#endif

#if VMG_MULTIPLICITY && defined(USE_ITHREADS) && defined(dMY_CXT) && defined(MY_CXT) && defined(START_MY_CXT) && defined(MY_CXT_INIT) && (defined(MY_CXT_CLONE) || defined(dMY_CXT_SV))
# define VMG_THREADSAFE 1
# ifndef MY_CXT_CLONE
#  define MY_CXT_CLONE \
    dMY_CXT_SV;                                                      \
    my_cxt_t *my_cxtp = (my_cxt_t*)SvPVX(newSV(sizeof(my_cxt_t)-1)); \
    Copy(INT2PTR(my_cxt_t*, SvUV(my_cxt_sv)), my_cxtp, 1, my_cxt_t); \
    sv_setuv(my_cxt_sv, PTR2UV(my_cxtp))
# endif
#else
# define VMG_THREADSAFE 0
# undef  dMY_CXT
# define dMY_CXT      dNOOP
# undef  MY_CXT
# define MY_CXT       vmg_globaldata
# undef  START_MY_CXT
# define START_MY_CXT STATIC my_cxt_t MY_CXT;
# undef  MY_CXT_INIT
# define MY_CXT_INIT  NOOP
# undef  MY_CXT_CLONE
# define MY_CXT_CLONE NOOP
#endif

#if VMG_THREADSAFE
# define VMG_LOCK(M)   MUTEX_LOCK(M)
# define VMG_UNLOCK(M) MUTEX_UNLOCK(M)
#else
# define VMG_LOCK(M)
# define VMG_UNLOCK(M)
#endif

/* --- Compatibility ------------------------------------------------------- */

#ifndef Newx
# define Newx(v, n, c) New(0, v, n, c)
#endif

#ifndef SvMAGIC_set
# define SvMAGIC_set(sv, val) (SvMAGIC(sv) = (val))
#endif

#ifndef SvRV_const
# define SvRV_const(sv) SvRV((SV *) sv)
#endif

#ifndef SvREFCNT_inc_simple_void
# define SvREFCNT_inc_simple_void(sv) ((void) SvREFCNT_inc(sv))
#endif

#ifndef mPUSHu
# define mPUSHu(U) PUSHs(sv_2mortal(newSVuv(U)))
#endif

#ifndef PERL_MAGIC_ext
# define PERL_MAGIC_ext '~'
#endif

#ifndef PERL_MAGIC_tied
# define PERL_MAGIC_tied 'P'
#endif

#ifndef MGf_LOCAL
# define MGf_LOCAL 0
#endif

#ifndef IN_PERL_COMPILETIME
# define IN_PERL_COMPILETIME (PL_curcop == &PL_compiling)
#endif

/* uvar magic and Hash::Util::FieldHash were commited with 28419, but we only
 * enable them on 5.10 */
#if VMG_HAS_PERL(5, 10, 0)
# define VMG_UVAR 1
#else
# define VMG_UVAR 0
#endif

#if VMG_HAS_PERL_MAINT(5, 11, 0, 32969) || VMG_HAS_PERL(5, 12, 0)
# define VMG_COMPAT_SCALAR_LENGTH_NOLEN 1
#else
# define VMG_COMPAT_SCALAR_LENGTH_NOLEN 0
#endif

#if VMG_HAS_PERL(5, 17, 4)
# define VMG_COMPAT_SCALAR_NOLEN 1
#else
# define VMG_COMPAT_SCALAR_NOLEN 0
#endif

/* Applied to dev-5.9 as 25854, integrated to maint-5.8 as 28160, partially
 * reverted to dev-5.11 as 9cdcb38b */
#if VMG_HAS_PERL_MAINT(5, 8, 9, 28160) || VMG_HAS_PERL_MAINT(5, 9, 3, 25854) || VMG_HAS_PERL(5, 10, 0)
# ifndef VMG_COMPAT_ARRAY_PUSH_NOLEN
#  if VMG_HAS_PERL(5, 11, 0)
#   define VMG_COMPAT_ARRAY_PUSH_NOLEN 0
#  else
#   define VMG_COMPAT_ARRAY_PUSH_NOLEN 1
#  endif
# endif
# ifndef VMG_COMPAT_ARRAY_PUSH_NOLEN_VOID
#  define VMG_COMPAT_ARRAY_PUSH_NOLEN_VOID 1
# endif
#else
# ifndef VMG_COMPAT_ARRAY_PUSH_NOLEN
#  define VMG_COMPAT_ARRAY_PUSH_NOLEN 0
# endif
# ifndef VMG_COMPAT_ARRAY_PUSH_NOLEN_VOID
#  define VMG_COMPAT_ARRAY_PUSH_NOLEN_VOID 0
# endif
#endif

/* Applied to dev-5.11 as 34908 */
#if VMG_HAS_PERL_MAINT(5, 11, 0, 34908) || VMG_HAS_PERL(5, 12, 0)
# define VMG_COMPAT_ARRAY_UNSHIFT_NOLEN_VOID 1
#else
# define VMG_COMPAT_ARRAY_UNSHIFT_NOLEN_VOID 0
#endif

/* Applied to dev-5.9 as 31473 (see #43357), integrated to maint-5.8 as 32542 */
#if VMG_HAS_PERL_MAINT(5, 8, 9, 32542) || VMG_HAS_PERL_MAINT(5, 9, 5, 31473) || VMG_HAS_PERL(5, 10, 0)
# define VMG_COMPAT_ARRAY_UNDEF_CLEAR 1
#else
# define VMG_COMPAT_ARRAY_UNDEF_CLEAR 0
#endif

#if VMG_HAS_PERL(5, 11, 0)
# define VMG_COMPAT_HASH_DELETE_NOUVAR_VOID 1
#else
# define VMG_COMPAT_HASH_DELETE_NOUVAR_VOID 0
#endif

#if VMG_HAS_PERL(5, 17, 0)
# define VMG_COMPAT_CODE_COPY_CLONE 1
#else
# define VMG_COMPAT_CODE_COPY_CLONE 0
#endif

#if VMG_HAS_PERL(5, 13, 2)
# define VMG_COMPAT_GLOB_GET 1
#else
# define VMG_COMPAT_GLOB_GET 0
#endif

#define VMG_PROPAGATE_ERRSV_NEEDS_TRAMPOLINE (VMG_HAS_PERL(5, 10, 0) && !VMG_HAS_PERL(5, 10, 1))

/* NewOp() isn't public in perl 5.8.0. */
#define VMG_RESET_RMG_NEEDS_TRAMPOLINE (VMG_UVAR && (VMG_THREADSAFE || !VMG_HAS_PERL(5, 8, 1)))

/* ... Bug-free mg_magical ................................................. */

/* See the discussion at http://www.xray.mpe.mpg.de/mailing-lists/perl5-porters/2008-01/msg00036.html */

#if VMG_HAS_PERL(5, 11, 3)

#define vmg_mg_magical(S) mg_magical(S)

#else

STATIC void vmg_mg_magical(SV *sv) {
 const MAGIC *mg;

 SvMAGICAL_off(sv);
 if ((mg = SvMAGIC(sv))) {
  do {
   const MGVTBL* const vtbl = mg->mg_virtual;
   if (vtbl) {
    if (vtbl->svt_get && !(mg->mg_flags & MGf_GSKIP))
     SvGMAGICAL_on(sv);
    if (vtbl->svt_set)
     SvSMAGICAL_on(sv);
    if (vtbl->svt_clear)
     SvRMAGICAL_on(sv);
   }
  } while ((mg = mg->mg_moremagic));
  if (!(SvFLAGS(sv) & (SVs_GMG|SVs_SMG)))
   SvRMAGICAL_on(sv);
 }
}

#endif

/* --- Trampoline ops ------------------------------------------------------ */

#define VMG_NEEDS_TRAMPOLINE VMG_PROPAGATE_ERRSV_NEEDS_TRAMPOLINE || VMG_RESET_RMG_NEEDS_TRAMPOLINE

#if VMG_NEEDS_TRAMPOLINE

typedef struct {
 OP   temp;
 SVOP target;
} vmg_trampoline;

STATIC void vmg_trampoline_init(vmg_trampoline *t, OP *(*cb)(pTHX)) {
 t->temp.op_type    = OP_STUB;
 t->temp.op_ppaddr  = 0;
 t->temp.op_next    = (OP *) &t->target;
 t->temp.op_flags   = 0;
 t->temp.op_private = 0;

 t->target.op_type    = OP_STUB;
 t->target.op_ppaddr  = cb;
 t->target.op_next    = NULL;
 t->target.op_flags   = 0;
 t->target.op_private = 0;
 t->target.op_sv      = NULL;
}

STATIC OP *vmg_trampoline_bump(pTHX_ vmg_trampoline *t, SV *sv, OP *o) {
#define vmg_trampoline_bump(T, S, O) vmg_trampoline_bump(aTHX_ (T), (S), (O))
 t->temp         = *o;
 t->temp.op_next = (OP *) &t->target;

 t->target.op_sv   = sv;
 t->target.op_next = o->op_next;

 return &t->temp;
}

#endif /* VMG_NEEDS_TRAMPOLINE */

/* --- Safe version of call_sv() ------------------------------------------- */

STATIC I32 vmg_call_sv(pTHX_ SV *sv, I32 flags, int (*cleanup)(pTHX_ void *), void *ud) {
#define vmg_call_sv(S, F, C, U) vmg_call_sv(aTHX_ (S), (F), (C), (U))
 I32 ret, cxix;
 PERL_CONTEXT saved_cx;
 SV *old_err = NULL;

 if (SvTRUE(ERRSV)) {
  old_err = ERRSV;
  ERRSV   = newSV(0);
 }

 cxix     = (cxstack_ix < cxstack_max) ? (cxstack_ix + 1) : Perl_cxinc(aTHX);
 /* The last popped context will be reused by call_sv(), but our callers may
  * still need its previous value. Back it up so that it isn't clobbered. */
 saved_cx = cxstack[cxix];

 ret = call_sv(sv, flags | G_EVAL);

 cxstack[cxix] = saved_cx;

 if (SvTRUE(ERRSV)) {
  if (old_err) {
   sv_setsv(old_err, ERRSV);
   SvREFCNT_dec(ERRSV);
   ERRSV = old_err;
  }
  if (IN_PERL_COMPILETIME) {
   if (!PL_in_eval) {
    if (PL_errors)
     sv_catsv(PL_errors, ERRSV);
    else
     Perl_warn(aTHX_ "%s", SvPV_nolen(ERRSV));
    SvCUR_set(ERRSV, 0);
   }
#if VMG_HAS_PERL(5, 10, 0) || defined(PL_parser)
   if (PL_parser)
    ++PL_parser->error_count;
#elif defined(PL_error_count)
   ++PL_error_count;
#else
   ++PL_Ierror_count;
#endif
  } else {
   if (!cleanup || cleanup(aTHX_ ud))
    croak(NULL);
  }
 } else {
  if (old_err) {
   SvREFCNT_dec(ERRSV);
   ERRSV = old_err;
  }
 }

 return ret;
}

/* --- Stolen chunk of B --------------------------------------------------- */

typedef enum {
 OPc_NULL,
 OPc_BASEOP,
 OPc_UNOP,
 OPc_BINOP,
 OPc_LOGOP,
 OPc_LISTOP,
 OPc_PMOP,
 OPc_SVOP,
 OPc_PADOP,
 OPc_PVOP,
 OPc_LOOP,
 OPc_COP,
#if VMG_HAS_PERL(5, 21, 5)
 OPc_METHOP,
#endif
 OPc_MAX
} opclass;

STATIC const char *const vmg_opclassnames[] = {
 "B::NULL",
 "B::OP",
 "B::UNOP",
 "B::BINOP",
 "B::LOGOP",
 "B::LISTOP",
 "B::PMOP",
 "B::SVOP",
 "B::PADOP",
 "B::PVOP",
 "B::LOOP",
 "B::COP",
#if VMG_HAS_PERL(5, 21, 5)
 "B::METHOP",
#endif
 NULL
};

STATIC opclass vmg_opclass(const OP *o) {
#if 0
 if (!o)
  return OPc_NULL;
#endif

 if (o->op_type == 0)
  return (o->op_flags & OPf_KIDS) ? OPc_UNOP : OPc_BASEOP;

 if (o->op_type == OP_SASSIGN)
  return ((o->op_private & OPpASSIGN_BACKWARDS) ? OPc_UNOP : OPc_BINOP);

 if (o->op_type == OP_AELEMFAST) {
#if PERL_VERSION <= 14
  if (o->op_flags & OPf_SPECIAL)
   return OPc_BASEOP;
  else
#endif
#ifdef USE_ITHREADS
   return OPc_PADOP;
#else
   return OPc_SVOP;
#endif
 }

#ifdef USE_ITHREADS
 if (o->op_type == OP_GV || o->op_type == OP_GVSV || o->op_type == OP_RCATLINE)
  return OPc_PADOP;
#endif

 switch (PL_opargs[o->op_type] & OA_CLASS_MASK) {
  case OA_BASEOP:
   return OPc_BASEOP;
  case OA_UNOP:
   return OPc_UNOP;
  case OA_BINOP:
   return OPc_BINOP;
  case OA_LOGOP:
   return OPc_LOGOP;
  case OA_LISTOP:
   return OPc_LISTOP;
  case OA_PMOP:
   return OPc_PMOP;
  case OA_SVOP:
   return OPc_SVOP;
  case OA_PADOP:
   return OPc_PADOP;
  case OA_PVOP_OR_SVOP:
   return (o->op_private & (OPpTRANS_TO_UTF|OPpTRANS_FROM_UTF)) ? OPc_SVOP : OPc_PVOP;
  case OA_LOOP:
   return OPc_LOOP;
  case OA_COP:
   return OPc_COP;
  case OA_BASEOP_OR_UNOP:
   return (o->op_flags & OPf_KIDS) ? OPc_UNOP : OPc_BASEOP;
  case OA_FILESTATOP:
   return ((o->op_flags & OPf_KIDS) ? OPc_UNOP :
#ifdef USE_ITHREADS
           (o->op_flags & OPf_REF) ? OPc_PADOP : OPc_BASEOP);
#else
           (o->op_flags & OPf_REF) ? OPc_SVOP : OPc_BASEOP);
#endif
  case OA_LOOPEXOP:
   if (o->op_flags & OPf_STACKED)
    return OPc_UNOP;
   else if (o->op_flags & OPf_SPECIAL)
    return OPc_BASEOP;
   else
    return OPc_PVOP;
#if VMG_HAS_PERL(5, 21, 5)
  case OA_METHOP:
   return OPc_METHOP;
#endif
 }

 return OPc_BASEOP;
}

/* --- Error messages ------------------------------------------------------ */

STATIC const char vmg_invalid_wiz[]    = "Invalid wizard object";
STATIC const char vmg_wrongargnum[]    = "Wrong number of arguments";
STATIC const char vmg_argstorefailed[] = "Error while storing arguments";

/* --- Context-safe global data -------------------------------------------- */

#define MY_CXT_KEY __PACKAGE__ "::_guts" XS_VERSION

typedef struct {
 HV             *b__op_stashes[OPc_MAX];
 I32             depth;
 MAGIC          *freed_tokens;
#if VMG_PROPAGATE_ERRSV_NEEDS_TRAMPOLINE
 vmg_trampoline  propagate_errsv;
#endif
#if VMG_RESET_RMG_NEEDS_TRAMPOLINE
 vmg_trampoline  reset_rmg;
#endif
} my_cxt_t;

START_MY_CXT

/* --- <vmg_vtable> structure ---------------------------------------------- */

#if VMG_THREADSAFE

typedef struct {
 MGVTBL *vtbl;
 U32     refcount;
} vmg_vtable;

STATIC vmg_vtable *vmg_vtable_alloc(pTHX) {
#define vmg_vtable_alloc() vmg_vtable_alloc(aTHX)
 vmg_vtable *t;

 t = VOID2(vmg_vtable *, PerlMemShared_malloc(sizeof *t));

 t->vtbl     = VOID2(MGVTBL *, PerlMemShared_malloc(sizeof *t->vtbl));
 t->refcount = 1;

 return t;
}

#define vmg_vtable_vtbl(T) (T)->vtbl

STATIC perl_mutex vmg_vtable_refcount_mutex;

STATIC vmg_vtable *vmg_vtable_dup(pTHX_ vmg_vtable *t) {
#define vmg_vtable_dup(T) vmg_vtable_dup(aTHX_ (T))
 VMG_LOCK(&vmg_vtable_refcount_mutex);
 ++t->refcount;
 VMG_UNLOCK(&vmg_vtable_refcount_mutex);

 return t;
}

STATIC void vmg_vtable_free(pTHX_ vmg_vtable *t) {
#define vmg_vtable_free(T) vmg_vtable_free(aTHX_ (T))
 U32 refcount;

 VMG_LOCK(&vmg_vtable_refcount_mutex);
 refcount = --t->refcount;
 VMG_UNLOCK(&vmg_vtable_refcount_mutex);

 if (!refcount) {
  PerlMemShared_free(t->vtbl);
  PerlMemShared_free(t);
 }
}

#else /* VMG_THREADSAFE */

typedef MGVTBL vmg_vtable;

STATIC vmg_vtable *vmg_vtable_alloc(pTHX) {
#define vmg_vtable_alloc() vmg_vtable_alloc(aTHX)
 vmg_vtable *t;

 Newx(t, 1, vmg_vtable);

 return t;
}

#define vmg_vtable_vtbl(T) ((MGVTBL *) (T))

#define vmg_vtable_free(T) Safefree(T)

#endif /* !VMG_THREADSAFE */

/* --- <vmg_wizard> structure ---------------------------------------------- */

typedef struct {
 vmg_vtable *vtable;

 U8 opinfo;
 U8 uvar;

 SV *cb_data;
 SV *cb_get, *cb_set, *cb_len, *cb_clear, *cb_free;
 SV *cb_copy;
 SV *cb_dup;
#if MGf_LOCAL
 SV *cb_local;
#endif /* MGf_LOCAL */
#if VMG_UVAR
 SV *cb_fetch, *cb_store, *cb_exists, *cb_delete;
#endif /* VMG_UVAR */
} vmg_wizard;

STATIC void vmg_op_info_init(pTHX_ unsigned int opinfo);

STATIC vmg_wizard *vmg_wizard_alloc(pTHX_ UV opinfo) {
#define vmg_wizard_alloc(O) vmg_wizard_alloc(aTHX_ (O))
 vmg_wizard *w;

 Newx(w, 1, vmg_wizard);

 w->uvar   = 0;
 w->opinfo = (U8) ((opinfo < 255) ? opinfo : 255);
 if (w->opinfo)
  vmg_op_info_init(aTHX_ w->opinfo);

 w->vtable = vmg_vtable_alloc();

 return w;
}

STATIC void vmg_wizard_free(pTHX_ vmg_wizard *w) {
#define vmg_wizard_free(W) vmg_wizard_free(aTHX_ (W))
 if (!w)
  return;

 /* During global destruction, any of the callbacks may already have been
  * freed, so we can't rely on still being able to access them. */
 if (!PL_dirty) {
  SvREFCNT_dec(w->cb_data);
  SvREFCNT_dec(w->cb_get);
  SvREFCNT_dec(w->cb_set);
  SvREFCNT_dec(w->cb_len);
  SvREFCNT_dec(w->cb_clear);
  SvREFCNT_dec(w->cb_free);
  SvREFCNT_dec(w->cb_copy);
#if 0
  SvREFCNT_dec(w->cb_dup);
#endif
#if MGf_LOCAL
  SvREFCNT_dec(w->cb_local);
#endif /* MGf_LOCAL */
#if VMG_UVAR
  SvREFCNT_dec(w->cb_fetch);
  SvREFCNT_dec(w->cb_store);
  SvREFCNT_dec(w->cb_exists);
  SvREFCNT_dec(w->cb_delete);
#endif /* VMG_UVAR */
 }

 /* PerlMemShared_free() and Safefree() are still fine during global
  * destruction though. */
 vmg_vtable_free(w->vtable);
 Safefree(w);

 return;
}

#if VMG_THREADSAFE

#define VMG_CLONE_CB(N) \
 z->cb_ ## N = (w->cb_ ## N) ? SvREFCNT_inc(sv_dup(w->cb_ ## N, params)) \
                             : NULL;

STATIC const vmg_wizard *vmg_wizard_dup(pTHX_ const vmg_wizard *w, CLONE_PARAMS *params) {
#define vmg_wizard_dup(W, P) vmg_wizard_dup(aTHX_ (W), (P))
 vmg_wizard *z;

 if (!w)
  return NULL;

 Newx(z, 1, vmg_wizard);

 z->vtable = vmg_vtable_dup(w->vtable);
 z->uvar   = w->uvar;
 z->opinfo = w->opinfo;

 VMG_CLONE_CB(data);
 VMG_CLONE_CB(get);
 VMG_CLONE_CB(set);
 VMG_CLONE_CB(len);
 VMG_CLONE_CB(clear);
 VMG_CLONE_CB(free);
 VMG_CLONE_CB(copy);
 VMG_CLONE_CB(dup);
#if MGf_LOCAL
 VMG_CLONE_CB(local);
#endif /* MGf_LOCAL */
#if VMG_UVAR
 VMG_CLONE_CB(fetch);
 VMG_CLONE_CB(store);
 VMG_CLONE_CB(exists);
 VMG_CLONE_CB(delete);
#endif /* VMG_UVAR */

 return z;
}

#endif /* VMG_THREADSAFE */

#define vmg_wizard_id(W) PTR2IV(vmg_vtable_vtbl((W)->vtable))

/* --- Wizard SV objects --------------------------------------------------- */

STATIC int vmg_wizard_sv_free(pTHX_ SV *sv, MAGIC *mg) {
 vmg_wizard_free((vmg_wizard *) mg->mg_ptr);

 return 0;
}

#if VMG_THREADSAFE

STATIC int vmg_wizard_sv_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *params) {
 mg->mg_ptr = (char *) vmg_wizard_dup((const vmg_wizard *) mg->mg_ptr, params);

 return 0;
}

#endif /* VMG_THREADSAFE */

STATIC MGVTBL vmg_wizard_sv_vtbl = {
 NULL,               /* get */
 NULL,               /* set */
 NULL,               /* len */
 NULL,               /* clear */
 vmg_wizard_sv_free, /* free */
 NULL,               /* copy */
#if VMG_THREADSAFE
 vmg_wizard_sv_dup,  /* dup */
#else
 NULL,               /* dup */
#endif
#if MGf_LOCAL
 NULL,               /* local */
#endif /* MGf_LOCAL */
};

STATIC SV *vmg_wizard_sv_new(pTHX_ const vmg_wizard *w) {
#define vmg_wizard_sv_new(W) vmg_wizard_sv_new(aTHX_ (W))
 SV *wiz;

#if VMG_THREADSAFE
 wiz = newSV(0);
#else
 wiz = newSViv(PTR2IV(w));
#endif

 if (w) {
  MAGIC *mg = sv_magicext(wiz, NULL, PERL_MAGIC_ext, &vmg_wizard_sv_vtbl,
                                     (const char *) w, 0);
  mg->mg_private = 0;
#if VMG_THREADSAFE
  mg->mg_flags  |= MGf_DUP;
#endif
 }
 SvREADONLY_on(wiz);

 return wiz;
}

#if VMG_THREADSAFE

#define vmg_sv_has_wizard_type(S) (SvTYPE(S) >= SVt_PVMG)

STATIC const vmg_wizard *vmg_wizard_from_sv_nocheck(const SV *wiz) {
 MAGIC *mg;

 for (mg = SvMAGIC(wiz); mg; mg = mg->mg_moremagic) {
  if (mg->mg_type == PERL_MAGIC_ext && mg->mg_virtual == &vmg_wizard_sv_vtbl)
   return (const vmg_wizard *) mg->mg_ptr;
 }

 return NULL;
}

#else /* VMG_THREADSAFE */

#define vmg_sv_has_wizard_type(S) SvIOK(S)

#define vmg_wizard_from_sv_nocheck(W) INT2PTR(const vmg_wizard *, SvIVX(W))

#endif /* !VMG_THREADSAFE */

#define vmg_wizard_from_sv(W) (vmg_sv_has_wizard_type(W) ? vmg_wizard_from_sv_nocheck(W) : NULL)

STATIC const vmg_wizard *vmg_wizard_from_mg(const MAGIC *mg) {
 if (mg->mg_type == PERL_MAGIC_ext && mg->mg_len == HEf_SVKEY) {
  SV *sv = (SV *) mg->mg_ptr;

  if (vmg_sv_has_wizard_type(sv))
   return vmg_wizard_from_sv_nocheck(sv);
 }

 return NULL;
}

#define vmg_wizard_from_mg_nocheck(M) vmg_wizard_from_sv_nocheck((const SV *) (M)->mg_ptr)

/* --- User-level functions implementation --------------------------------- */

STATIC const MAGIC *vmg_find(const SV *sv, const vmg_wizard *w) {
 const MAGIC *mg;
 IV wid;

 if (SvTYPE(sv) < SVt_PVMG)
  return NULL;

 wid = vmg_wizard_id(w);

 for (mg = SvMAGIC(sv); mg; mg = mg->mg_moremagic) {
  const vmg_wizard *z = vmg_wizard_from_mg(mg);

  if (z && vmg_wizard_id(z) == wid)
   return mg;
 }

 return NULL;
}

/* ... Construct private data .............................................. */

STATIC SV *vmg_data_new(pTHX_ SV *ctor, SV *sv, SV **args, I32 items) {
#define vmg_data_new(C, S, A, I) vmg_data_new(aTHX_ (C), (S), (A), (I))
 I32 i;
 SV *nsv;

 dSP;

 ENTER;
 SAVETMPS;

 PUSHMARK(SP);
 EXTEND(SP, items + 1);
 PUSHs(sv_2mortal(newRV_inc(sv)));
 for (i = 0; i < items; ++i)
  PUSHs(args[i]);
 PUTBACK;

 vmg_call_sv(ctor, G_SCALAR, 0, NULL);

 SPAGAIN;
 nsv = POPs;
#if VMG_HAS_PERL(5, 8, 3)
 SvREFCNT_inc_simple_void(nsv); /* Or it will be destroyed in FREETMPS */
#else
 nsv = sv_newref(nsv);          /* Workaround some bug in SvREFCNT_inc() */
#endif
 PUTBACK;

 FREETMPS;
 LEAVE;

 return nsv;
}

STATIC SV *vmg_data_get(pTHX_ SV *sv, const vmg_wizard *w) {
#define vmg_data_get(S, W) vmg_data_get(aTHX_ (S), (W))
 const MAGIC *mg = vmg_find(sv, w);

 return mg ? mg->mg_obj : NULL;
}

/* ... Magic cast/dispell .................................................. */

#if VMG_UVAR

STATIC I32 vmg_svt_val(pTHX_ IV, SV *);

typedef struct {
 struct ufuncs new_uf;
 struct ufuncs old_uf;
} vmg_uvar_ud;

#endif /* VMG_UVAR */

STATIC void vmg_mg_del(pTHX_ SV *sv, MAGIC *prevmagic, MAGIC *mg, MAGIC *moremagic) {
#define vmg_mg_del(S, P, M, N) vmg_mg_del(aTHX_ (S), (P), (M), (N))
 dMY_CXT;

 if (prevmagic)
  prevmagic->mg_moremagic = moremagic;
 else
  SvMAGIC_set(sv, moremagic);

 /* Destroy private data */
#if VMG_UVAR
 if (mg->mg_type == PERL_MAGIC_uvar) {
  Safefree(mg->mg_ptr);
 } else {
#endif /* VMG_UVAR */
  if (mg->mg_obj != sv) {
   SvREFCNT_dec(mg->mg_obj);
   mg->mg_obj = NULL;
  }
  /* Unreference the wizard */
  SvREFCNT_dec((SV *) mg->mg_ptr);
  mg->mg_ptr = NULL;
#if VMG_UVAR
 }
#endif /* VMG_UVAR */

 if (MY_CXT.depth) {
  mg->mg_moremagic    = MY_CXT.freed_tokens;
  MY_CXT.freed_tokens = mg;
 } else {
  mg->mg_moremagic = NULL;
  Safefree(mg);
 }
}

STATIC int vmg_magic_chain_free(pTHX_ MAGIC *mg, MAGIC *skip) {
#define vmg_magic_chain_free(M, S) vmg_magic_chain_free(aTHX_ (M), (S))
 int skipped = 0;

 while (mg) {
  MAGIC *moremagic = mg->mg_moremagic;

  if (mg == skip)
   ++skipped;
  else
   Safefree(mg);

  mg = moremagic;
 }

 return skipped;
}

STATIC UV vmg_cast(pTHX_ SV *sv, const vmg_wizard *w, const SV *wiz, SV **args, I32 items) {
#define vmg_cast(S, W, WIZ, A, I) vmg_cast(aTHX_ (S), (W), (WIZ), (A), (I))
 MAGIC  *mg;
 MGVTBL *t;
 SV     *data;
 U32     oldgmg;

 if (vmg_find(sv, w))
  return 1;

 oldgmg = SvGMAGICAL(sv);

 data = (w->cb_data) ? vmg_data_new(w->cb_data, sv, args, items) : NULL;

 t  = vmg_vtable_vtbl(w->vtable);
 mg = sv_magicext(sv, data, PERL_MAGIC_ext, t, (const char *) wiz, HEf_SVKEY);
 mg->mg_private = 0;

 /* sv_magicext() calls mg_magical and increments data's refcount */
 SvREFCNT_dec(data);

 if (t->svt_copy)
  mg->mg_flags |= MGf_COPY;
#if 0
 if (t->svt_dup)
  mg->mg_flags |= MGf_DUP;
#endif
#if MGf_LOCAL
 if (t->svt_local)
  mg->mg_flags |= MGf_LOCAL;
#endif /* MGf_LOCAL */

 if (SvTYPE(sv) < SVt_PVHV)
  goto done;

 /* The GMAGICAL flag only says that a hash is tied or has uvar magic - get
  * magic is actually never called for them. If the GMAGICAL flag was off before
  * calling sv_magicext(), the hash isn't tied and has no uvar magic. If it's
  * now on, then this wizard has get magic. Hence we can work around the
  * get/clear shortcoming by turning the GMAGICAL flag off. If the current magic
  * has uvar callbacks, it will be turned back on later. */
 if (!oldgmg && SvGMAGICAL(sv))
  SvGMAGICAL_off(sv);

#if VMG_UVAR
 if (w->uvar) {
  MAGIC *prevmagic, *moremagic = NULL;
  vmg_uvar_ud ud;

  ud.new_uf.uf_val   = vmg_svt_val;
  ud.new_uf.uf_set   = NULL;
  ud.new_uf.uf_index = 0;
  ud.old_uf.uf_val   = NULL;
  ud.old_uf.uf_set   = NULL;
  ud.old_uf.uf_index = 0;

  /* One uvar magic in the chain is enough. */
  for (prevmagic = NULL, mg = SvMAGIC(sv); mg; prevmagic = mg, mg = moremagic) {
   moremagic = mg->mg_moremagic;
   if (mg->mg_type == PERL_MAGIC_uvar)
    break;
  }

  if (mg) { /* Found another uvar magic. */
   struct ufuncs *uf = (struct ufuncs *) mg->mg_ptr;
   if (uf->uf_val == vmg_svt_val) {
    /* It's our uvar magic, nothing to do. oldgmg was true. */
    goto done;
   } else {
    /* It's another uvar magic, backup it and replace it by ours. */
    ud.old_uf = *uf;
    vmg_mg_del(sv, prevmagic, mg, moremagic);
   }
  }

  sv_magic(sv, NULL, PERL_MAGIC_uvar, (const char *) &ud, sizeof(ud));
  vmg_mg_magical(sv);
  /* Our hash now carries uvar magic. The uvar/clear shortcoming has to be
   * handled by our uvar callback. */
 }
#endif /* VMG_UVAR */

done:
 return 1;
}

STATIC UV vmg_dispell(pTHX_ SV *sv, const vmg_wizard *w) {
#define vmg_dispell(S, W) vmg_dispell(aTHX_ (S), (W))
#if VMG_UVAR
 U32 uvars = 0;
#endif /* VMG_UVAR */
 MAGIC *mg, *prevmagic, *moremagic = NULL;
 IV wid = vmg_wizard_id(w);

 if (SvTYPE(sv) < SVt_PVMG)
  return 0;

 for (prevmagic = NULL, mg = SvMAGIC(sv); mg; prevmagic = mg, mg = moremagic) {
  const vmg_wizard *z;

  moremagic = mg->mg_moremagic;

  z = vmg_wizard_from_mg(mg);
  if (z) {
   IV zid = vmg_wizard_id(z);

#if VMG_UVAR
   if (zid == wid) {
    /* If the current has no uvar, short-circuit uvar deletion. */
    uvars = z->uvar ? (uvars + 1) : 0;
    break;
   } else if (z->uvar) {
    ++uvars;
    /* We can't break here since we need to find the ext magic to delete. */
   }
#else /* VMG_UVAR */
   if (zid == wid)
    break;
#endif /* !VMG_UVAR */
  }
 }
 if (!mg)
  return 0;

 vmg_mg_del(sv, prevmagic, mg, moremagic);

#if VMG_UVAR
 if (uvars == 1 && SvTYPE(sv) >= SVt_PVHV) {
  /* mg was the first ext magic in the chain that had uvar */

  for (mg = moremagic; mg; mg = mg->mg_moremagic) {
   const vmg_wizard *z = vmg_wizard_from_mg(mg);

   if (z && z->uvar) {
    ++uvars;
    break;
   }
  }

  if (uvars == 1) {
   vmg_uvar_ud *ud;

   for (prevmagic = NULL, mg = SvMAGIC(sv); mg; prevmagic = mg, mg = moremagic){
    moremagic = mg->mg_moremagic;
    if (mg->mg_type == PERL_MAGIC_uvar)
     break;
   }

   ud = (vmg_uvar_ud *) mg->mg_ptr;
   if (ud->old_uf.uf_val || ud->old_uf.uf_set) {
    /* Revert the original uvar magic. */
    struct ufuncs *uf;
    Newx(uf, 1, struct ufuncs);
    *uf = ud->old_uf;
    Safefree(ud);
    mg->mg_ptr = (char *) uf;
    mg->mg_len = sizeof(*uf);
   } else {
    /* Remove the uvar magic. */
    vmg_mg_del(sv, prevmagic, mg, moremagic);
   }
  }
 }
#endif /* VMG_UVAR */

 vmg_mg_magical(sv);

 return 1;
}

/* ... OP info ............................................................. */

#define VMG_OP_INFO_NAME   1
#define VMG_OP_INFO_OBJECT 2

#if VMG_THREADSAFE
STATIC perl_mutex vmg_op_name_init_mutex;
#endif

STATIC U32           vmg_op_name_init      = 0;
STATIC unsigned char vmg_op_name_len[MAXO] = { 0 };

STATIC void vmg_op_info_init(pTHX_ unsigned int opinfo) {
#define vmg_op_info_init(W) vmg_op_info_init(aTHX_ (W))
 switch (opinfo) {
  case VMG_OP_INFO_NAME:
   VMG_LOCK(&vmg_op_name_init_mutex);
   if (!vmg_op_name_init) {
    OPCODE t;
    for (t = 0; t < OP_max; ++t)
     vmg_op_name_len[t] = strlen(PL_op_name[t]);
    vmg_op_name_init = 1;
   }
   VMG_UNLOCK(&vmg_op_name_init_mutex);
   break;
  case VMG_OP_INFO_OBJECT: {
   dMY_CXT;
   if (!MY_CXT.b__op_stashes[0]) {
    int c;
    require_pv("B.pm");
    for (c = OPc_NULL; c < OPc_MAX; ++c)
     MY_CXT.b__op_stashes[c] = gv_stashpv(vmg_opclassnames[c], 1);
   }
   break;
  }
  default:
   break;
 }
}

STATIC SV *vmg_op_info(pTHX_ unsigned int opinfo) {
#define vmg_op_info(W) vmg_op_info(aTHX_ (W))
 if (!PL_op)
  return &PL_sv_undef;

 switch (opinfo) {
  case VMG_OP_INFO_NAME: {
   OPCODE t = PL_op->op_type;
   return sv_2mortal(newSVpvn(PL_op_name[t], vmg_op_name_len[t]));
  }
  case VMG_OP_INFO_OBJECT: {
   dMY_CXT;
   return sv_bless(sv_2mortal(newRV_noinc(newSViv(PTR2IV(PL_op)))),
                   MY_CXT.b__op_stashes[vmg_opclass(PL_op)]);
  }
  default:
   break;
 }

 return &PL_sv_undef;
}

/* --- svt callbacks ------------------------------------------------------- */

#define VMG_CB_CALL_ARGS_MASK  15
#define VMG_CB_CALL_ARGS_SHIFT 4
#define VMG_CB_CALL_OPINFO     (VMG_OP_INFO_NAME|VMG_OP_INFO_OBJECT) /* 1|2 */
#define VMG_CB_CALL_GUARD      4

STATIC int vmg_dispell_guard_oncroak(pTHX_ void *ud) {
 dMY_CXT;

 MY_CXT.depth--;

 /* If we're at the upmost magic call and we're about to die, we can just free
  * the tokens right now, since we will jump past the problematic part of our
  * caller. */
 if (MY_CXT.depth == 0 && MY_CXT.freed_tokens) {
  vmg_magic_chain_free(MY_CXT.freed_tokens, NULL);
  MY_CXT.freed_tokens = NULL;
 }

 return 1;
}

STATIC int vmg_dispell_guard_free(pTHX_ SV *sv, MAGIC *mg) {
 vmg_magic_chain_free((MAGIC *) mg->mg_ptr, NULL);

 return 0;
}

#if VMG_THREADSAFE

STATIC int vmg_dispell_guard_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *params) {
 /* The freed magic tokens aren't cloned by perl because it cannot reach them
  * (they have been detached from their parent SV when they were enqueued).
  * Hence there's nothing to purge in the new thread. */
 mg->mg_ptr = NULL;

 return 0;
}

#endif /* VMG_THREADSAFE */

STATIC MGVTBL vmg_dispell_guard_vtbl = {
 NULL,                   /* get */
 NULL,                   /* set */
 NULL,                   /* len */
 NULL,                   /* clear */
 vmg_dispell_guard_free, /* free */
 NULL,                   /* copy */
#if VMG_THREADSAFE
 vmg_dispell_guard_dup,  /* dup */
#else
 NULL,                   /* dup */
#endif
#if MGf_LOCAL
 NULL,                   /* local */
#endif /* MGf_LOCAL */
};

STATIC SV *vmg_dispell_guard_new(pTHX_ MAGIC *root) {
#define vmg_dispell_guard_new(R) vmg_dispell_guard_new(aTHX_ (R))
 SV *guard;

 guard = sv_newmortal();
 sv_magicext(guard, NULL, PERL_MAGIC_ext, &vmg_dispell_guard_vtbl,
                          (char *) root, 0);

 return guard;
}

STATIC int vmg_cb_call(pTHX_ SV *cb, unsigned int flags, SV *sv, ...) {
 va_list ap;
 int ret = 0;
 unsigned int i, args, opinfo;
 MAGIC **chain = NULL;
 SV *svr;

 dSP;

 args    = flags & VMG_CB_CALL_ARGS_MASK;
 flags >>= VMG_CB_CALL_ARGS_SHIFT;
 opinfo  = flags & VMG_CB_CALL_OPINFO;

 ENTER;
 SAVETMPS;

 PUSHMARK(SP);
 EXTEND(SP, args + 1);
 PUSHs(sv_2mortal(newRV_inc(sv)));
 va_start(ap, sv);
 for (i = 0; i < args; ++i) {
  SV *sva = va_arg(ap, SV *);
  PUSHs(sva ? sva : &PL_sv_undef);
 }
 va_end(ap);
 if (opinfo)
  XPUSHs(vmg_op_info(opinfo));
 PUTBACK;

 if (flags & VMG_CB_CALL_GUARD) {
  dMY_CXT;
  MY_CXT.depth++;
  vmg_call_sv(cb, G_SCALAR, vmg_dispell_guard_oncroak, NULL);
  MY_CXT.depth--;
  if (MY_CXT.depth == 0 && MY_CXT.freed_tokens)
   chain = &MY_CXT.freed_tokens;
 } else {
  vmg_call_sv(cb, G_SCALAR, 0, NULL);
 }

 SPAGAIN;
 svr = POPs;
 if (SvOK(svr))
  ret = (int) SvIV(svr);
 PUTBACK;

 FREETMPS;
 LEAVE;

 if (chain) {
  vmg_dispell_guard_new(*chain);
  *chain = NULL;
 }

 return ret;
}

#define VMG_CB_FLAGS(OI, A) \
        ((((unsigned int) (OI)) << VMG_CB_CALL_ARGS_SHIFT) | (A))

#define vmg_cb_call1(I, OI, S, A1) \
        vmg_cb_call(aTHX_ (I), VMG_CB_FLAGS((OI), 1), (S), (A1))
#define vmg_cb_call2(I, OI, S, A1, A2) \
        vmg_cb_call(aTHX_ (I), VMG_CB_FLAGS((OI), 2), (S), (A1), (A2))
#define vmg_cb_call3(I, OI, S, A1, A2, A3) \
        vmg_cb_call(aTHX_ (I), VMG_CB_FLAGS((OI), 3), (S), (A1), (A2), (A3))

/* ... Default no-op magic callback ........................................ */

STATIC int vmg_svt_default_noop(pTHX_ SV *sv, MAGIC *mg) {
 return 0;
}

/* ... get magic ........................................................... */

STATIC int vmg_svt_get(pTHX_ SV *sv, MAGIC *mg) {
 const vmg_wizard *w = vmg_wizard_from_mg_nocheck(mg);

 return vmg_cb_call1(w->cb_get, w->opinfo, sv, mg->mg_obj);
}

#define vmg_svt_get_noop vmg_svt_default_noop

/* ... set magic ........................................................... */

STATIC int vmg_svt_set(pTHX_ SV *sv, MAGIC *mg) {
 const vmg_wizard *w = vmg_wizard_from_mg_nocheck(mg);

 return vmg_cb_call1(w->cb_set, w->opinfo, sv, mg->mg_obj);
}

#define vmg_svt_set_noop vmg_svt_default_noop

/* ... len magic ........................................................... */

STATIC U32 vmg_sv_len(pTHX_ SV *sv) {
#define vmg_sv_len(S) vmg_sv_len(aTHX_ (S))
 STRLEN len;
#if VMG_HAS_PERL(5, 9, 3)
 const U8 *s = VOID2(const U8 *, VOID2(const void *, SvPV_const(sv, len)));
#else
 U8 *s = SvPV(sv, len);
#endif

 return DO_UTF8(sv) ? utf8_length(s, s + len) : len;
}

STATIC U32 vmg_svt_len(pTHX_ SV *sv, MAGIC *mg) {
 const vmg_wizard *w = vmg_wizard_from_mg_nocheck(mg);
 unsigned int opinfo = w->opinfo;
 U32 len, ret;
 SV *svr;
 svtype t = SvTYPE(sv);

 dSP;

 ENTER;
 SAVETMPS;

 PUSHMARK(SP);
 EXTEND(SP, 3);
 PUSHs(sv_2mortal(newRV_inc(sv)));
 PUSHs(mg->mg_obj ? mg->mg_obj : &PL_sv_undef);
 if (t < SVt_PVAV) {
  len = vmg_sv_len(sv);
  mPUSHu(len);
 } else if (t == SVt_PVAV) {
  len = av_len((AV *) sv) + 1;
  mPUSHu(len);
 } else {
  len = 0;
  PUSHs(&PL_sv_undef);
 }
 if (opinfo)
  XPUSHs(vmg_op_info(opinfo));
 PUTBACK;

 vmg_call_sv(w->cb_len, G_SCALAR, 0, NULL);

 SPAGAIN;
 svr = POPs;
 ret = SvOK(svr) ? (U32) SvUV(svr) : len;
 if (t == SVt_PVAV)
  --ret;
 PUTBACK;

 FREETMPS;
 LEAVE;

 return ret;
}

STATIC U32 vmg_svt_len_noop(pTHX_ SV *sv, MAGIC *mg) {
 U32    len = 0;
 svtype t   = SvTYPE(sv);

 if (t < SVt_PVAV) {
  len = vmg_sv_len(sv);
 } else if (t == SVt_PVAV) {
  len = (U32) av_len((AV *) sv);
 }

 return len;
}

/* ... clear magic ......................................................... */

STATIC int vmg_svt_clear(pTHX_ SV *sv, MAGIC *mg) {
 const vmg_wizard *w = vmg_wizard_from_mg_nocheck(mg);
 unsigned int flags  = w->opinfo;

#if !VMG_HAS_PERL(5, 12, 0)
 flags |= VMG_CB_CALL_GUARD;
#endif

 return vmg_cb_call1(w->cb_clear, flags, sv, mg->mg_obj);
}

#define vmg_svt_clear_noop vmg_svt_default_noop

/* ... free magic .......................................................... */

#if VMG_PROPAGATE_ERRSV_NEEDS_TRAMPOLINE

STATIC OP *vmg_pp_propagate_errsv(pTHX) {
 SVOP *o = cSVOPx(PL_op);

 if (o->op_sv) {
  SvREFCNT_dec(ERRSV);
  ERRSV    = o->op_sv;
  o->op_sv = NULL;
 }

 return NORMAL;
}

#endif /* VMG_PROPAGATE_ERRSV_NEEDS_TRAMPOLINE */

STATIC int vmg_propagate_errsv_free(pTHX_ SV *sv, MAGIC *mg) {
 if (mg->mg_obj) {
  ERRSV         = mg->mg_obj;
  mg->mg_obj    = NULL;
  mg->mg_flags &= ~MGf_REFCOUNTED;
 }

 return 0;
}

/* perl is already kind enough to handle the cloning of the mg_obj member,
   hence we don't need to define a dup magic callback. */

STATIC MGVTBL vmg_propagate_errsv_vtbl = {
 0,                        /* get */
 0,                        /* set */
 0,                        /* len */
 0,                        /* clear */
 vmg_propagate_errsv_free, /* free */
 0,                        /* copy */
 0,                        /* dup */
#if MGf_LOCAL
 0,                        /* local */
#endif /* MGf_LOCAL */
};

typedef struct {
 SV  *sv;
 int  in_eval;
 I32  base;
} vmg_svt_free_cleanup_ud;

STATIC int vmg_svt_free_cleanup(pTHX_ void *ud_) {
 vmg_svt_free_cleanup_ud *ud = VOID2(vmg_svt_free_cleanup_ud *, ud_);

 if (ud->in_eval) {
  U32 optype = PL_op ? PL_op->op_type : OP_NULL;

  if (optype == OP_LEAVETRY || optype == OP_LEAVEEVAL) {
   SV *errsv = newSVsv(ERRSV);

   FREETMPS;
   LEAVE_SCOPE(ud->base);

#if VMG_PROPAGATE_ERRSV_NEEDS_TRAMPOLINE
   if (optype == OP_LEAVETRY) {
    dMY_CXT;
    PL_op = vmg_trampoline_bump(&MY_CXT.propagate_errsv, errsv, PL_op);
   } else if (optype == OP_LEAVEEVAL) {
    SV *guard = sv_newmortal();
    sv_magicext(guard, errsv, PERL_MAGIC_ext, &vmg_propagate_errsv_vtbl,
                              NULL, 0);
   }
#else /* !VMG_PROPAGATE_ERRSV_NEEDS_TRAMPOLINE */
# if !VMG_HAS_PERL(5, 8, 9)
   {
    SV *guard = sv_newmortal();
    sv_magicext(guard, errsv, PERL_MAGIC_ext, &vmg_propagate_errsv_vtbl,
                              NULL, 0);
   }
# else
   sv_magicext(ERRSV, errsv, PERL_MAGIC_ext, &vmg_propagate_errsv_vtbl,
                             NULL, 0);
   SvREFCNT_dec(errsv);
# endif
#endif /* VMG_PROPAGATE_ERRSV_NEEDS_TRAMPOLINE */

   SAVETMPS;
  }

  /* Don't propagate */
  return 0;
 } else {
  SV    *sv = ud->sv;
  MAGIC *mg;

  /* We are about to croak() while sv is being destroyed. Try to clean up
   * things a bit. */
  mg = SvMAGIC(sv);
  if (mg) {
   vmg_mg_del(sv, NULL, mg, mg->mg_moremagic);
   mg_magical(sv);
  }
  SvREFCNT_dec(sv);

  vmg_dispell_guard_oncroak(aTHX_ NULL);

  /* After that, propagate the error upwards. */
  return 1;
 }
}

STATIC int vmg_svt_free(pTHX_ SV *sv, MAGIC *mg) {
 vmg_svt_free_cleanup_ud ud;
 const vmg_wizard *w;
 int ret = 0;
 SV *svr;

 dSP;

 /* During global destruction, we cannot be sure that the wizard and its free
  * callback are still alive. */
 if (PL_dirty)
  return 0;

 w = vmg_wizard_from_mg_nocheck(mg);

 /* So that it survives the temp cleanup below */
 SvREFCNT_inc_simple_void(sv);

#if !(VMG_HAS_PERL_MAINT(5, 11, 0, 32686) || VMG_HAS_PERL(5, 12, 0))
 /* The previous magic tokens were freed but the magic chain wasn't updated, so
  * if you access the sv from the callback the old deleted magics will trigger
  * and cause memory misreads. Change 32686 solved it that way : */
 SvMAGIC_set(sv, mg);
#endif

 ud.sv = sv;
 if (cxstack_ix < cxstack_max) {
  ud.in_eval = (CxTYPE(cxstack + cxstack_ix + 1) == CXt_EVAL);
  ud.base    = ud.in_eval ? PL_scopestack[PL_scopestack_ix] : 0;
 } else {
  ud.in_eval = 0;
  ud.base    = 0;
 }

 ENTER;
 SAVETMPS;

 PUSHMARK(SP);
 EXTEND(SP, 2);
 PUSHs(sv_2mortal(newRV_inc(sv)));
 PUSHs(mg->mg_obj ? mg->mg_obj : &PL_sv_undef);
 if (w->opinfo)
  XPUSHs(vmg_op_info(w->opinfo));
 PUTBACK;

 {
  dMY_CXT;
  MY_CXT.depth++;
  vmg_call_sv(w->cb_free, G_SCALAR, vmg_svt_free_cleanup, &ud);
  MY_CXT.depth--;
  if (MY_CXT.depth == 0 && MY_CXT.freed_tokens) {
   /* Free all the tokens in the chain but the current one (if it's present).
    * It will be taken care of by our caller, Perl_mg_free(). */
   vmg_magic_chain_free(MY_CXT.freed_tokens, mg);
   MY_CXT.freed_tokens = NULL;
  }
 }

 SPAGAIN;
 svr = POPs;
 if (SvOK(svr))
  ret = (int) SvIV(svr);
 PUTBACK;

 FREETMPS;
 LEAVE;

 /* Calling SvREFCNT_dec() will trigger destructors in an infinite loop, so
  * we have to rely on SvREFCNT() being a lvalue. Heck, even the core does it */
 --SvREFCNT(sv);

 /* Perl_mg_free will get rid of the magic and decrement mg->mg_obj and
  * mg->mg_ptr reference count */
 return ret;
}

#define vmg_svt_free_noop vmg_svt_default_noop

#if VMG_HAS_PERL_MAINT(5, 11, 0, 33256) || VMG_HAS_PERL(5, 12, 0)
# define VMG_SVT_COPY_KEYLEN_TYPE I32
#else
# define VMG_SVT_COPY_KEYLEN_TYPE int
#endif

/* ... copy magic .......................................................... */

STATIC int vmg_svt_copy(pTHX_ SV *sv, MAGIC *mg, SV *nsv, const char *key, VMG_SVT_COPY_KEYLEN_TYPE keylen) {
 const vmg_wizard *w = vmg_wizard_from_mg_nocheck(mg);
 SV *keysv;
 int ret;

 if (keylen == HEf_SVKEY) {
  keysv = (SV *) key;
 } else {
  keysv = newSVpvn(key, keylen);
 }

 if (SvTYPE(sv) >= SVt_PVCV)
  nsv = sv_2mortal(newRV_inc(nsv));

 ret = vmg_cb_call3(w->cb_copy, w->opinfo, sv, mg->mg_obj, keysv, nsv);

 if (keylen != HEf_SVKEY) {
  SvREFCNT_dec(keysv);
 }

 return ret;
}

STATIC int vmg_svt_copy_noop(pTHX_ SV *sv, MAGIC *mg, SV *nsv, const char *key, VMG_SVT_COPY_KEYLEN_TYPE keylen) {
 return 0;
}

/* ... dup magic ........................................................... */

#if 0
STATIC int vmg_svt_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *param) {
 return 0;
}
#define vmg_svt_dup_noop vmg_svt_dup
#endif

/* ... local magic ......................................................... */

#if MGf_LOCAL

STATIC int vmg_svt_local(pTHX_ SV *nsv, MAGIC *mg) {
 const vmg_wizard *w = vmg_wizard_from_mg_nocheck(mg);

 return vmg_cb_call1(w->cb_local, w->opinfo, nsv, mg->mg_obj);
}

#define vmg_svt_local_noop vmg_svt_default_noop

#endif /* MGf_LOCAL */

/* ... uvar magic .......................................................... */

#if VMG_UVAR

STATIC OP *vmg_pp_reset_rmg(pTHX) {
 SVOP *o = cSVOPx(PL_op);

 SvRMAGICAL_on(o->op_sv);
 o->op_sv = NULL;

 return NORMAL;
}

STATIC I32 vmg_svt_val(pTHX_ IV action, SV *sv) {
 vmg_uvar_ud *ud;
 MAGIC *mg, *umg, *moremagic;
 SV *key = NULL, *newkey = NULL;
 int tied = 0;

 umg = mg_find(sv, PERL_MAGIC_uvar);
 /* umg can't be NULL or we wouldn't be there. */
 key = umg->mg_obj;
 ud  = (vmg_uvar_ud *) umg->mg_ptr;

 if (ud->old_uf.uf_val)
  ud->old_uf.uf_val(aTHX_ action, sv);
 if (ud->old_uf.uf_set)
  ud->old_uf.uf_set(aTHX_ action, sv);

 for (mg = SvMAGIC(sv); mg; mg = moremagic) {
  const vmg_wizard *w;

  /* mg may be freed later by the uvar call, so we need to fetch the next
   * token before reaching that fateful point. */
  moremagic = mg->mg_moremagic;

  switch (mg->mg_type) {
   case PERL_MAGIC_ext:
    break;
   case PERL_MAGIC_tied:
    ++tied;
    continue;
   default:
    continue;
  }

  w = vmg_wizard_from_mg(mg);
  if (!w)
   continue;

  switch (w->uvar) {
   case 0:
    continue;
   case 2:
    if (!newkey)
     newkey = key = umg->mg_obj = sv_mortalcopy(umg->mg_obj);
  }

  switch (action
             & (HV_FETCH_ISSTORE|HV_FETCH_ISEXISTS|HV_FETCH_LVALUE|HV_DELETE)) {
   case 0:
    if (w->cb_fetch)
     vmg_cb_call2(w->cb_fetch, w->opinfo | VMG_CB_CALL_GUARD, sv,
                               mg->mg_obj, key);
    break;
   case HV_FETCH_ISSTORE:
   case HV_FETCH_LVALUE:
   case (HV_FETCH_ISSTORE|HV_FETCH_LVALUE):
    if (w->cb_store)
     vmg_cb_call2(w->cb_store, w->opinfo | VMG_CB_CALL_GUARD, sv,
                               mg->mg_obj, key);
    break;
   case HV_FETCH_ISEXISTS:
    if (w->cb_exists)
     vmg_cb_call2(w->cb_exists, w->opinfo | VMG_CB_CALL_GUARD, sv,
                                mg->mg_obj, key);
    break;
   case HV_DELETE:
    if (w->cb_delete)
     vmg_cb_call2(w->cb_delete, w->opinfo | VMG_CB_CALL_GUARD, sv,
                                mg->mg_obj, key);
    break;
  }
 }

 if (SvRMAGICAL(sv) && !tied && !(action & (HV_FETCH_ISSTORE|HV_DELETE))) {
  /* Temporarily hide the RMAGICAL flag of the hash so it isn't wrongly
   * mistaken for a tied hash by the rest of hv_common. It will be reset by
   * the op_ppaddr of a new fake op injected between the current and the next
   * one. */

#if VMG_RESET_RMG_NEEDS_TRAMPOLINE

  dMY_CXT;

  PL_op = vmg_trampoline_bump(&MY_CXT.reset_rmg, sv, PL_op);

#else /* !VMG_RESET_RMG_NEEDS_TRAMPOLINE */

  OP   *nop  = PL_op->op_next;
  SVOP *svop = NULL;

  if (nop && nop->op_ppaddr == vmg_pp_reset_rmg) {
   svop = (SVOP *) nop;
  } else {
   NewOp(1101, svop, 1, SVOP);
   svop->op_type    = OP_STUB;
   svop->op_ppaddr  = vmg_pp_reset_rmg;
   svop->op_next    = nop;
   svop->op_flags   = 0;
   svop->op_private = 0;

   PL_op->op_next = (OP *) svop;
  }

  svop->op_sv = sv;

#endif /* VMG_RESET_RMG_NEEDS_TRAMPOLINE */

  SvRMAGICAL_off(sv);
 }

 return 0;
}

#endif /* VMG_UVAR */

/* --- Macros for the XS section ------------------------------------------- */

#ifdef CvISXSUB
# define VMG_CVOK(C) \
   ((CvISXSUB(C) ? (void *) CvXSUB(C) : (void *) CvROOT(C)) ? 1 : 0)
#else
# define VMG_CVOK(C) (CvROOT(C) || CvXSUB(C))
#endif

#define VMG_CBOK(S) ((SvTYPE(S) == SVt_PVCV) ? VMG_CVOK(S) : SvOK(S))

#define VMG_SET_CB(S, N) {       \
 SV *cb = (S);                   \
 if (SvOK(cb) && SvROK(cb)) {    \
  cb = SvRV(cb);                 \
  if (VMG_CBOK(cb))              \
   SvREFCNT_inc_simple_void(cb); \
  else                           \
   cb = NULL;                    \
 } else {                        \
  cb = NULL;                     \
 }                               \
 w->cb_ ## N = cb;               \
}

#define VMG_SET_SVT_CB(S, N) {   \
 SV *cb = (S);                   \
 if (SvOK(cb) && SvROK(cb)) {    \
  cb = SvRV(cb);                 \
  if (VMG_CBOK(cb)) {            \
   t->svt_ ## N = vmg_svt_ ## N; \
   SvREFCNT_inc_simple_void(cb); \
  } else {                       \
   t->svt_ ## N = vmg_svt_ ## N ## _noop; \
   cb           = NULL;          \
  }                              \
 } else {                        \
  t->svt_ ## N = NULL;           \
  cb           = NULL;           \
 }                               \
 w->cb_ ## N = cb;               \
}

/* --- XS ------------------------------------------------------------------ */

MODULE = Variable::Magic            PACKAGE = Variable::Magic

PROTOTYPES: ENABLE

BOOT:
{
 HV *stash;
 int c;

 MY_CXT_INIT;
 for (c = OPc_NULL; c < OPc_MAX; ++c)
  MY_CXT.b__op_stashes[c] = NULL;

 MY_CXT.depth        = 0;
 MY_CXT.freed_tokens = NULL;

 /* XS doesn't like a blank line here */
#if VMG_PROPAGATE_ERRSV_NEEDS_TRAMPOLINE
 vmg_trampoline_init(&MY_CXT.propagate_errsv, vmg_pp_propagate_errsv);
#endif
#if VMG_RESET_RMG_NEEDS_TRAMPOLINE
 vmg_trampoline_init(&MY_CXT.reset_rmg, vmg_pp_reset_rmg);
#endif

 /* XS doesn't like a blank line here */
#if VMG_THREADSAFE
 MUTEX_INIT(&vmg_vtable_refcount_mutex);
 MUTEX_INIT(&vmg_op_name_init_mutex);
#endif

 stash = gv_stashpv(__PACKAGE__, 1);
 newCONSTSUB(stash, "MGf_COPY",  newSVuv(MGf_COPY));
 newCONSTSUB(stash, "MGf_DUP",   newSVuv(MGf_DUP));
 newCONSTSUB(stash, "MGf_LOCAL", newSVuv(MGf_LOCAL));
 newCONSTSUB(stash, "VMG_UVAR",  newSVuv(VMG_UVAR));
 newCONSTSUB(stash, "VMG_COMPAT_SCALAR_LENGTH_NOLEN",
                    newSVuv(VMG_COMPAT_SCALAR_LENGTH_NOLEN));
 newCONSTSUB(stash, "VMG_COMPAT_SCALAR_NOLEN",
                    newSVuv(VMG_COMPAT_SCALAR_NOLEN));
 newCONSTSUB(stash, "VMG_COMPAT_ARRAY_PUSH_NOLEN",
                    newSVuv(VMG_COMPAT_ARRAY_PUSH_NOLEN));
 newCONSTSUB(stash, "VMG_COMPAT_ARRAY_PUSH_NOLEN_VOID",
                    newSVuv(VMG_COMPAT_ARRAY_PUSH_NOLEN_VOID));
 newCONSTSUB(stash, "VMG_COMPAT_ARRAY_UNSHIFT_NOLEN_VOID",
                    newSVuv(VMG_COMPAT_ARRAY_UNSHIFT_NOLEN_VOID));
 newCONSTSUB(stash, "VMG_COMPAT_ARRAY_UNDEF_CLEAR",
                    newSVuv(VMG_COMPAT_ARRAY_UNDEF_CLEAR));
 newCONSTSUB(stash, "VMG_COMPAT_HASH_DELETE_NOUVAR_VOID",
                    newSVuv(VMG_COMPAT_HASH_DELETE_NOUVAR_VOID));
 newCONSTSUB(stash, "VMG_COMPAT_CODE_COPY_CLONE",
                    newSVuv(VMG_COMPAT_CODE_COPY_CLONE));
 newCONSTSUB(stash, "VMG_COMPAT_GLOB_GET", newSVuv(VMG_COMPAT_GLOB_GET));
 newCONSTSUB(stash, "VMG_PERL_PATCHLEVEL", newSVuv(VMG_PERL_PATCHLEVEL));
 newCONSTSUB(stash, "VMG_THREADSAFE",      newSVuv(VMG_THREADSAFE));
 newCONSTSUB(stash, "VMG_FORKSAFE",        newSVuv(VMG_FORKSAFE));
 newCONSTSUB(stash, "VMG_OP_INFO_NAME",    newSVuv(VMG_OP_INFO_NAME));
 newCONSTSUB(stash, "VMG_OP_INFO_OBJECT",  newSVuv(VMG_OP_INFO_OBJECT));
}

#if VMG_THREADSAFE

void
CLONE(...)
PROTOTYPE: DISABLE
PREINIT:
 U32 had_b__op_stash = 0;
 I32 old_depth;
 int c;
PPCODE:
 {
  dMY_CXT;
  for (c = OPc_NULL; c < OPc_MAX; ++c) {
   if (MY_CXT.b__op_stashes[c])
    had_b__op_stash |= (((U32) 1) << c);
  }
  old_depth = MY_CXT.depth;
 }
 {
  MY_CXT_CLONE;
  for (c = OPc_NULL; c < OPc_MAX; ++c) {
   MY_CXT.b__op_stashes[c] = (had_b__op_stash & (((U32) 1) << c))
                              ? gv_stashpv(vmg_opclassnames[c], 1) : NULL;
  }
  MY_CXT.depth        = old_depth;
  MY_CXT.freed_tokens = NULL;
 }
 XSRETURN(0);

#endif /* VMG_THREADSAFE */

SV *_wizard(...)
PROTOTYPE: DISABLE
PREINIT:
 vmg_wizard *w;
 MGVTBL *t;
 SV *op_info, *copy_key;
 I32 i = 0;
CODE:
 if (items != 9
#if MGf_LOCAL
              + 1
#endif /* MGf_LOCAL */
#if VMG_UVAR
              + 5
#endif /* VMG_UVAR */
              ) { croak(vmg_wrongargnum); }

 op_info = ST(i++);
 w = vmg_wizard_alloc(SvOK(op_info) ? SvUV(op_info) : 0);
 t = vmg_vtable_vtbl(w->vtable);

 VMG_SET_CB(ST(i++), data);

 VMG_SET_SVT_CB(ST(i++), get);
 VMG_SET_SVT_CB(ST(i++), set);
 VMG_SET_SVT_CB(ST(i++), len);
 VMG_SET_SVT_CB(ST(i++), clear);
 VMG_SET_SVT_CB(ST(i++), free);
 VMG_SET_SVT_CB(ST(i++), copy);
 /* VMG_SET_SVT_CB(ST(i++), dup); */
 i++;
 t->svt_dup = NULL;
 w->cb_dup  = NULL;
#if MGf_LOCAL
 VMG_SET_SVT_CB(ST(i++), local);
#endif /* MGf_LOCAL */
#if VMG_UVAR
 VMG_SET_CB(ST(i++), fetch);
 VMG_SET_CB(ST(i++), store);
 VMG_SET_CB(ST(i++), exists);
 VMG_SET_CB(ST(i++), delete);

 copy_key = ST(i++);
 if (w->cb_fetch || w->cb_store || w->cb_exists || w->cb_delete)
  w->uvar = SvTRUE(copy_key) ? 2 : 1;
#endif /* VMG_UVAR */

 RETVAL = newRV_noinc(vmg_wizard_sv_new(w));
OUTPUT:
 RETVAL

SV *cast(SV *sv, SV *wiz, ...)
PROTOTYPE: \[$@%&*]$@
PREINIT:
 const vmg_wizard *w = NULL;
 SV **args = NULL;
 I32 i = 0;
CODE:
 if (items > 2) {
  i = items - 2;
  args = &ST(2);
 }
 if (SvROK(wiz)) {
  wiz = SvRV_const(wiz);
  w   = vmg_wizard_from_sv(wiz);
 }
 if (!w)
  croak(vmg_invalid_wiz);
 RETVAL = newSVuv(vmg_cast(SvRV(sv), w, wiz, args, i));
OUTPUT:
 RETVAL

void
getdata(SV *sv, SV *wiz)
PROTOTYPE: \[$@%&*]$
PREINIT:
 const vmg_wizard *w = NULL;
 SV *data;
PPCODE:
 if (SvROK(wiz))
  w = vmg_wizard_from_sv(SvRV_const(wiz));
 if (!w)
  croak(vmg_invalid_wiz);
 data = vmg_data_get(SvRV(sv), w);
 if (!data)
  XSRETURN_EMPTY;
 ST(0) = data;
 XSRETURN(1);

SV *dispell(SV *sv, SV *wiz)
PROTOTYPE: \[$@%&*]$
PREINIT:
 const vmg_wizard *w = NULL;
CODE:
 if (SvROK(wiz))
  w = vmg_wizard_from_sv(SvRV_const(wiz));
 if (!w)
  croak(vmg_invalid_wiz);
 RETVAL = newSVuv(vmg_dispell(SvRV(sv), w));
OUTPUT:
 RETVAL
