import { themeQuartz } from '@ag-grid-community/theming';

const myTheme = themeQuartz
	.withParams({
        accentColor: "#00ABD7",
        borderColor: "#2881A43D",
        browserColorScheme: "light",
        fontFamily: {
            googleFont: "Inter"
        },
        headerBackgroundColor: "#00ABD7",
        headerFontFamily: {
            googleFont: "Inter"
        },
        headerFontSize: "16px",
        headerFontWeight: 600,
        headerTextColor: "#000000",
        headerVerticalPaddingScale: 1.02
    });

    export default myTheme;