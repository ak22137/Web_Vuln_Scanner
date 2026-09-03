from st_aggrid import AgGrid
from st_aggrid.grid_options_builder import GridOptionsBuilder
from st_aggrid.shared import GridUpdateMode, JsCode

MAX_TABLE_HEIGHT = 700


def get_numeric_style_with_precision(precision: int) -> dict:
    return {"type": ["numericColumn", "customNumericFormat"], "precision": precision}


PRECISION_ZERO = get_numeric_style_with_precision(0)
PRECISION_ONE = get_numeric_style_with_precision(1)
PRECISION_TWO = get_numeric_style_with_precision(2)
PINLEFT = {"pinned": "left"}


def draw_grid(
        df,
        formatter: dict = {},
        use_container_width: bool = True,

        use_checkbox=False,
        fit_columns=True,
        fit_columns_on_resize=True,
        theme="material",
        max_height: int = MAX_TABLE_HEIGHT,
        wrap_text: bool = False,
        auto_height: bool = True,
        grid_options: dict = None,
        width: int = 400,
        key=None,
        css: dict = {},
):

    gb = GridOptionsBuilder().from_dataframe(df)
    gb.configure_default_column(
        filterable=True,
        groupable=False,
        editable=False,
        wrapText=wrap_text,
        autoHeight=auto_height
    )

    if grid_options is not None:
        gb.configure_grid_options(**grid_options)

    for latin_name, (cyr_name, style_dict) in formatter.items():
        gb.configure_column(latin_name, header_name=cyr_name, **style_dict)

    # gb.configure_selection(selection_mode=selection, use_checkbox=use_checkbox)


    # if color_conditions:
    #     for condition in color_conditions:
    #         column = condition.get('column')
    #         color_map = condition.get('color_map')
    #         if column and color_map and column in df.columns:
    #             js_code = f"""
    #             function(params) {{
    #                 const val = params.value;
    #                 const colorFn = {str(color_map)};
    #                 return {{
    #                     'backgroundColor': colorFn(val)
    #                 }};
    #             }}
    #             """
    #             gb.configure_column(
    #                 column,
    #                 cellStyle=JsCode(js_code)
    #             )
    return AgGrid(
        df,
        gridOptions=gb.build(),
        update_mode=GridUpdateMode.VALUE_CHANGED,
        allow_unsafe_jscode=True,
        fit_columns_on_grid_load=fit_columns,
        fit_columns_on_resize=fit_columns_on_resize,
        height=min(max_height, (1 + len(df.index)) * 29),
        use_container_width=use_container_width,
        use_checkbox=use_checkbox,
        theme=theme,
        key=key,

        width=width,
        custom_css=css
    )


def highlight(color, condition):
    code = f"""
        function(params) {{
            color = "{color}";
            if ({condition}) {{
                return {{
                    'backgroundColor': color
                }}
            }}
        }};
    """
    return JsCode(code)