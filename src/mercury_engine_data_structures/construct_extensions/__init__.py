import operator

import construct.expr

# Workaround construct's bug (See issue #1039)
construct.expr.opnames[operator.and_] = "&"
construct.expr.opnames[operator.or_] = "|"
