import construct
from construct import FocusedSeq, stream_tell, Construct, Optional, Const


def Skip(count, subcon):
    return construct.Seek(count * subcon.length, 1)


class LazyPatchedForBug(construct.Lazy):
    r"""
    See https://github.com/construct/construct/issues/938
    """

    def _parse(self, stream, context, path):
        offset = stream_tell(stream, path)

        def execute():
            fallback = stream_tell(stream, path)
            construct.stream_seek(stream, offset, 0, path)
            obj = self.subcon._parsereport(stream, context, path)
            construct.stream_seek(stream, fallback, 0, path)
            return obj

        length = self.subcon._actualsize(stream, context, path)
        construct.stream_seek(stream, length, 1, path)
        return execute


class ErrorWithMessage(Construct):
    def __init__(self, message, error=construct.ExplicitError):
        super().__init__()
        self.message = message
        self.flagbuildnone = True
        self.error = error

    def _parse(self, stream, context, path):
        message = construct.evaluate(self.message, context)
        raise self.error(f"Error field was activated during parsing with error {message}", path=path)

    def _build(self, obj, stream, context, path):
        message = construct.evaluate(self.message, context)
        raise self.error(f"Error field was activated during building with error {message}", path=path)

    def _sizeof(self, context, path):
        raise construct.SizeofError("Error does not have size, because it interrupts parsing and building", path=path)


def ForceQuit():
    def force_quit(ctx):
        raise SystemExit(1)

    return ErrorWithMessage(force_quit)


def LabeledOptional(label, subcon):
    return Optional(
        FocusedSeq(
            "subcon",
            Const(label),
            "subcon" / subcon,
        )
    )


def OptionalValue(subcon):
    return construct.FocusedSeq(
        "value",
        present=construct.Rebuild(construct.Flag, construct.this.value != None),
        value=construct.If(construct.this.present, subcon),
    )
