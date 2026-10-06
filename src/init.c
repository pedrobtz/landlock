#define R_NO_REMAP
#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

SEXP C_lk_ll_abi(void);

static const R_CallMethodDef call_methods[] = {
    {"C_lk_ll_abi", (DL_FUNC) &C_lk_ll_abi, 0},
    {NULL, NULL, 0}
};

void R_init_landlock(DllInfo *dll)
{
    R_registerRoutines(dll, NULL, call_methods, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
}
