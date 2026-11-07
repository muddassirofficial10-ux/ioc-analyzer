from django import template

register = template.Library()


@register.filter
def display(value):
    """Lists become comma-separated text; everything else is shown as-is."""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return value


@register.filter
def label(value):
    """'not_configured' -> 'not configured'."""
    return str(value).replace("_", " ")


@register.filter
def defanged(value):
    """Show an indicator so it can't be clicked or auto-linked by accident."""
    from analyzer.indicators import defang

    return defang(str(value))
