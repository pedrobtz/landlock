/* .Call adapters over the C core. The only file in src/ that includes R
 * headers (design.md §3). */
#define R_NO_REMAP
#include <R.h>
#include <Rinternals.h>
#include "lk.h"

SEXP C_lk_ll_abi(void)
{
    return Rf_ScalarInteger(lk_ll_abi());
}
