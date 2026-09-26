import { ColorMode } from "@chakra-ui/react";

export const updateThemeColor = (colorMode: ColorMode) => {
  const el = document.querySelector('meta[name="theme-color"]');
  el?.setAttribute('content', colorMode == "dark" ? "#0b1018" : "#0369a1");
};
