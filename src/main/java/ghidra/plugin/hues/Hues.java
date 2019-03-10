package ghidra.plugin.hues;

import javax.swing.*;
import javax.swing.plaf.ColorUIResource;
import javax.swing.plaf.metal.DefaultMetalTheme;
import javax.swing.plaf.metal.MetalLookAndFeel;
import javax.swing.plaf.metal.MetalTheme;
import java.awt.*;

/**
 * @author quosego <https://github.com/quosego>
 * @version Mar 10, 2019
 */
public class Hues extends DefaultMetalTheme {
  private static MetalTheme theme;
  private HuesColors defaultColors;
  private HuesColors modifiedColors;

  public Hues() {
    super();
    setupDefaultColors();
    this.modifiedColors = new HuesColors(0, 0, 0);
  }

  public Hues(Color color) {
    super();
    setupDefaultColors();
    this.modifiedColors = new HuesColors(color);
  }

  public Hues(HuesColors color) {
    super();
    setupDefaultColors();
    this.modifiedColors =
        new HuesColors(color.getBrightness(), color.getHue(), color.getSaturation());
  }

  public Hues(DefaultMetalTheme theme) {
    super();
    setupDefaultColors();
    this.modifiedColors = new HuesColors(theme.getControl());
  }

  public Hues(int brightness, int saturation, int hue) {
    super();
    setupDefaultColors();
    this.modifiedColors = new HuesColors(brightness, saturation, hue);
  }

  private void setupDefaultColors() {
    theme = new DefaultMetalTheme();
    ColorUIResource ui = theme.getControl();
    float[] off = Color.RGBtoHSB(ui.getRed(), ui.getGreen(), ui.getBlue(), null);
    this.defaultColors = new HuesColors(off[2], off[1], off[0]);
  }

  public HuesColors getModifiedHueColors() {
    return this.modifiedColors;
  }

  public HuesColors getDefaultHueColors() {
    return this.defaultColors;
  }

  public ColorUIResource changeColor(ColorUIResource existing) {
    return this.defaultColors.changeColorResource(existing, this.modifiedColors);
  }

  public void updateHueColors(float brightness, float saturation, float hue) {
    this.modifiedColors.setColor(brightness, saturation, hue);
  }

  public void activate() {
    try {
      MetalLookAndFeel.setCurrentTheme(this);
      UIManager.setLookAndFeel(MetalLookAndFeel.class.getName());
    } catch (Exception e) {
      throw new AssertionError(e);
    }
    SwingUtilities.invokeLater(
        new Runnable() {
          @Override
          public void run() {
            for (Window window : Window.getWindows()) {
              SwingUtilities.updateComponentTreeUI(window);
            }
          }
        });
  }

  // ==================================================================================================
  // MetalTheme methods
  // ==================================================================================================

  public ColorUIResource getFocusColor() {
    return changeColor(theme.getFocusColor());
  }

  public ColorUIResource getDesktopColor() {
    return changeColor(theme.getDesktopColor());
  }

  public ColorUIResource getControl() {
    return changeColor(theme.getControl());
  }

  public ColorUIResource getControlShadow() {
    return changeColor(theme.getControlShadow());
  }

  public ColorUIResource getControlDarkShadow() {
    return changeColor(theme.getControlDarkShadow());
  }

  public ColorUIResource getControlInfo() {
    return changeColor(theme.getControlInfo());
  }

  public ColorUIResource getControlHighlight() {
    return changeColor(theme.getControlHighlight());
  }

  public ColorUIResource getControlDisabled() {
    return changeColor(theme.getControlDisabled());
  }

  public ColorUIResource getPrimaryControl() {
    return changeColor(theme.getPrimaryControl());
  }

  public ColorUIResource getPrimaryControlShadow() {
    return changeColor(theme.getPrimaryControlShadow());
  }

  public ColorUIResource getPrimaryControlDarkShadow() {
    return changeColor(theme.getPrimaryControlDarkShadow());
  }

  public ColorUIResource getPrimaryControlInfo() {
    return changeColor(theme.getPrimaryControlInfo());
  }

  public ColorUIResource getPrimaryControlHighlight() {
    return changeColor(theme.getPrimaryControlHighlight());
  }

  public ColorUIResource getSystemTextColor() {
    return changeColor(theme.getSystemTextColor());
  }

  public ColorUIResource getControlTextColor() {
    return changeColor(theme.getControlTextColor());
  }

  public ColorUIResource getInactiveControlTextColor() {
    return changeColor(theme.getInactiveControlTextColor());
  }

  public ColorUIResource getInactiveSystemTextColor() {
    return changeColor(theme.getInactiveSystemTextColor());
  }

  public ColorUIResource getUserTextColor() {
    return changeColor(theme.getUserTextColor());
  }

  public ColorUIResource getTextHighlightColor() {
    return changeColor(theme.getTextHighlightColor());
  }

  public ColorUIResource getHighlightedTextColor() {
    return changeColor(theme.getHighlightedTextColor());
  }

  public ColorUIResource getWindowBackground() {
    return changeColor(theme.getWindowBackground());
  }

  public ColorUIResource getWindowTitleBackground() {
    return changeColor(theme.getWindowTitleBackground());
  }

  public ColorUIResource getWindowTitleForeground() {
    return changeColor(theme.getWindowTitleForeground());
  }

  public ColorUIResource getWindowTitleInactiveBackground() {
    return changeColor(theme.getWindowTitleInactiveBackground());
  }

  public ColorUIResource getWindowTitleInactiveForeground() {
    return changeColor(theme.getWindowTitleInactiveForeground());
  }

  public ColorUIResource getMenuBackground() {
    return changeColor(theme.getMenuBackground());
  }

  public ColorUIResource getMenuForeground() {
    return changeColor(theme.getMenuForeground());
  }

  public ColorUIResource getMenuSelectedBackground() {
    return changeColor(theme.getMenuSelectedBackground());
  }

  public ColorUIResource getMenuSelectedForeground() {
    return changeColor(theme.getMenuSelectedForeground());
  }

  public ColorUIResource getMenuDisabledForeground() {
    return changeColor(theme.getMenuDisabledForeground());
  }

  public ColorUIResource getSeparatorBackground() {
    return changeColor(theme.getSeparatorBackground());
  }

  public ColorUIResource getSeparatorForeground() {
    return changeColor(theme.getSeparatorForeground());
  }

  public ColorUIResource getAcceleratorForeground() {
    return changeColor(theme.getAcceleratorForeground());
  }

  public ColorUIResource getAcceleratorSelectedForeground() {
    return changeColor(theme.getAcceleratorSelectedForeground());
  }

  // ==================================================================================================
  // Object methods
  // ==================================================================================================

  @Override
  public int hashCode() {
    return (int)
        (this.modifiedColors.getHue()
            + this.modifiedColors.getSaturation()
            + this.modifiedColors.getBrightness());
  }

  @Override
  public boolean equals(Object obj) {
    if ((obj instanceof Hues)) {
      Hues other = (Hues) obj;
      if (other != null) {
        if (other.getDefaultHueColors().equals(this.getDefaultHueColors())) {
          return true;
        }
      }
    }
    return false;
  }

  @Override
  public String toString() {
    return "{ "
        + getClass().getName()
        + ": { modified: "
        + this.modifiedColors
        + ", defaults: "
        + this.defaultColors
        + "}}";
  }
}
