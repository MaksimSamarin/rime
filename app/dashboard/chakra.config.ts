import { extendTheme } from "@chakra-ui/react";
export const theme = extendTheme({
  config: { initialColorMode: "dark", useSystemColorMode: false },
  shadows: { outline: "0 0 0 2px var(--chakra-colors-primary-200)" },
  fonts: {
    body: `Inter,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Oxygen,Ubuntu,Cantarell,Fira Sans,Droid Sans,Helvetica Neue,sans-serif`,
  },
  colors: {
    "light-border": "#d2d2d4",
    primary: {
      50: "#f0f9ff",
      100: "#e0f2fe",
      200: "#bae6fd",
      300: "#7dd3fc",
      400: "#38bdf8",
      500: "#0284c7",
      600: "#0369a1",
      700: "#075985",
      800: "#0c4a6e",
      900: "#082f49",
    },
    gray: {
      750: "#172332",
      800: "#111923",
      900: "#0b1018",
    },
  },
  components: {
    Alert: {
      baseStyle: {
        container: {
          borderRadius: "6px",
          fontSize: "sm",
        },
      },
    },
    Select: {
      baseStyle: {
        field: {
          _dark: {
            borderColor: "gray.600",
            borderRadius: "6px",
          },
          _light: {
            borderRadius: "6px",
          },
        },
      },
    },
    FormHelperText: {
      baseStyle: {
        fontSize: "xs",
      },
    },
    FormLabel: {
      baseStyle: {
        fontSize: "sm",
        fontWeight: "medium",
        mb: "1",
        _dark: { color: "gray.300" },
      },
    },
    Input: {
      baseStyle: {
        addon: {
          _dark: {
            borderColor: "gray.600",
            _placeholder: {
              color: "gray.500",
            },
          },
        },
        field: {
          _focusVisible: {
            boxShadow: "none",
            borderColor: "primary.200",
            outlineColor: "primary.200",
          },
          _dark: {
            borderColor: "gray.600",
            _disabled: {
              color: "gray.400",
              borderColor: "gray.500",
            },
            _placeholder: {
              color: "gray.500",
            },
          },
        },
      },
    },
    Table: {
      baseStyle: {
        table: {
          borderCollapse: "separate",
          borderSpacing: 0,
        },
        thead: {
          borderBottomColor: "light-border",
        },
        th: {
          background: "#F9FAFB",
          borderColor: "light-border !important",
          borderBottomColor: "light-border !important",
          borderTop: "1px solid ",
          borderTopColor: "light-border !important",
          _first: {
            borderLeft: "1px solid",
            borderColor: "light-border !important",
          },
          _last: {
            borderRight: "1px solid",
            borderColor: "light-border !important",
          },
          _dark: {
            borderColor: "gray.600 !important",
            background: "gray.750",
          },
        },
        td: {
          transition: "all .1s ease-out",
          borderColor: "light-border",
          borderBottomColor: "light-border !important",
          _first: {
            borderLeft: "1px solid",
            borderColor: "light-border",
            _dark: {
              borderColor: "gray.600",
            },
          },
          _last: {
            borderRight: "1px solid",
            borderColor: "light-border",
            _dark: {
              borderColor: "gray.600",
            },
          },
          _dark: {
            borderColor: "gray.600",
            borderBottomColor: "gray.600 !important",
          },
        },
        tr: {
          "&.interactive": {
            cursor: "pointer",
            _hover: {
              "& > td": {
                bg: "gray.200",
              },
              _dark: {
                "& > td": {
                  bg: "gray.750",
                },
              },
            },
          },
          _last: {
            "& > td": {
              _first: {
                borderBottomLeftRadius: "8px",
              },
              _last: {
                borderBottomRightRadius: "8px",
              },
            },
          },
        },
      },
    },
  },
});
