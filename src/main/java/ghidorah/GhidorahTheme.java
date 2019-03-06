package ghidorah;

import javax.swing.*;
import javax.swing.plaf.ColorUIResource;
import javax.swing.plaf.metal.DefaultMetalTheme;
import javax.swing.plaf.metal.MetalLookAndFeel;
import java.awt.*;

/**
 * @author quosego
 *
 */
public class GhidorahTheme extends DefaultMetalTheme {
    private static DefaultMetalTheme theme;
    private static float[] hsbOffset;
    private int hueOffset;
    private int saturationOffset;
    private int brightnessOffset;

    public GhidorahTheme(int hueOffset, int saturationOffset, int brightnessOffset) {
        super();
        setupTheme();
        setHueOffset(hueOffset);
        setSaturationOffset(saturationOffset);
        setBrightnessOffset(brightnessOffset);
    }

    private void setupTheme() {
        theme = new DefaultMetalTheme();
        ColorUIResource uiResource = theme.getControl();
        hsbOffset = Color.RGBtoHSB( uiResource.getRed(), uiResource.getGreen(), uiResource.getBlue(), null);
    }

    private void setHueOffset(int hueOffset) {
        this.hueOffset = hueOffset;
    }

    private void setSaturationOffset(int saturationOffset) {
        this.saturationOffset = saturationOffset;
    }

    private void setBrightnessOffset(int brightnessOffset) {
        this.brightnessOffset = brightnessOffset;
    }

    public static int getDefaultHueOffset() {
        return Math.round(hsbOffset[0] * 255);
    }

    public static int getDefaultSaturationOffset() {
        return Math.round(hsbOffset[1] * 255);
    }

    public static int getDefaultBrightnessOffset() {
        return Math.round(hsbOffset[2] * 255);
    }

    public int getHueOffset() {
        return this.hueOffset;
    }

    public int getSaturationOffset() {
        return this.saturationOffset;
    }

    public int getBrightnessOffset() {
        return this.brightnessOffset;
    }

    public Color adpapt(Color color) {
        return changeHSB255(color, this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    private ColorUIResource changeHSB255(Color color, int hue2555Offset, int saturation2555Offset, int brightness2555Offset) {
        float[] hsb = Color.RGBtoHSB(color.getRed(), color.getGreen(), color.getBlue(), null);

        hsb[0] = adjustHSBOverflow(hsb[0] - hsbOffset[0] + (hue2555Offset / 255f));
        hsb[1] = adjustHSBOverflow(hsb[1] - hsbOffset[1] + (saturation2555Offset / 255f));
        hsb[2] = adjustHSBOverflow(hsb[2] - hsbOffset[2] + (brightness2555Offset / 255f));

        int rgb = Color.HSBtoRGB(hsb[0], hsb[1], hsb[2]);
        return new ColorUIResource(rgb);
    }

    private float adjustHSBOverflow(float value) {
        if (value < 0.0) {
            return adjustHSBOverflow(-value);
        }
        if (value > 1.0) {
            return adjustHSBOverflow((float) Math.ceil(value) - value);
        }
        value = Math.round(value * 100f) / 100f;
        return value;
    }

    public ColorUIResource getFocusColor() {
        return changeHSB255(theme.getFocusColor(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getDesktopColor() {
        return changeHSB255(theme.getDesktopColor(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getControl() {
        return changeHSB255(theme.getControl(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getControlShadow() {
        return changeHSB255(theme.getControlShadow(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getControlDarkShadow() {
        return changeHSB255(theme.getControlDarkShadow(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getControlInfo() {
        return changeHSB255(theme.getControlInfo(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getControlHighlight() {
        return changeHSB255(theme.getControlHighlight(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getControlDisabled() {
        return changeHSB255(theme.getControlDisabled(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getPrimaryControl() {
        return changeHSB255(theme.getPrimaryControl(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getPrimaryControlShadow() {
        return changeHSB255(theme.getPrimaryControlShadow(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getPrimaryControlDarkShadow() {
        return changeHSB255(theme.getPrimaryControlDarkShadow(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getPrimaryControlInfo() {
        return changeHSB255(theme.getPrimaryControlInfo(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getPrimaryControlHighlight() {
        return changeHSB255(theme.getPrimaryControlHighlight(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getSystemTextColor() {
        return changeHSB255(theme.getSystemTextColor(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getControlTextColor() {
        return changeHSB255(theme.getControlTextColor(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getInactiveControlTextColor() {
        return changeHSB255(theme.getInactiveControlTextColor(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getInactiveSystemTextColor() {
        return changeHSB255(theme.getInactiveSystemTextColor(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getUserTextColor() {
        return changeHSB255(theme.getUserTextColor(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getTextHighlightColor() {
        return changeHSB255(theme.getTextHighlightColor(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getHighlightedTextColor() {
        return changeHSB255(theme.getHighlightedTextColor(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getWindowBackground() {
        return changeHSB255(theme.getWindowBackground(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getWindowTitleBackground() {
        return changeHSB255(theme.getWindowTitleBackground(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getWindowTitleForeground() {
        return changeHSB255(theme.getWindowTitleForeground(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getWindowTitleInactiveBackground() {
        return changeHSB255(theme.getWindowTitleInactiveBackground(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getWindowTitleInactiveForeground() {
        return changeHSB255(theme.getWindowTitleInactiveForeground(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getMenuBackground() {
        return changeHSB255(theme.getMenuBackground(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getMenuForeground() {
        return changeHSB255(theme.getMenuForeground(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getMenuSelectedBackground() {
        return changeHSB255(theme.getMenuSelectedBackground(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getMenuSelectedForeground() {
        return changeHSB255(theme.getMenuSelectedForeground(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getMenuDisabledForeground() {
        return changeHSB255(theme.getMenuDisabledForeground(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getSeparatorBackground() {
        return changeHSB255(theme.getSeparatorBackground(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getSeparatorForeground() {
        return changeHSB255(theme.getSeparatorForeground(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getAcceleratorForeground() {
        return changeHSB255(theme.getAcceleratorForeground(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    public ColorUIResource getAcceleratorSelectedForeground() {
        return changeHSB255(theme.getAcceleratorSelectedForeground(), this.hueOffset, this.saturationOffset, this.brightnessOffset);
    }

    private boolean isAlreadyActive() {
        LookAndFeel currentLAF = UIManager.getLookAndFeel();
        if (!(currentLAF instanceof MetalLookAndFeel)) {
            return false;
        }
        return this.equals(MetalLookAndFeel.getCurrentTheme());
    }

    public void activate() {
        if (isAlreadyActive()) {
            return;
        }
        try {
            MetalLookAndFeel.setCurrentTheme(this);
            UIManager.setLookAndFeel(MetalLookAndFeel.class.getName());
        } catch (Exception e) {
            throw new AssertionError(e);
        }
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                for (Window window : Window.getWindows()) {
                    SwingUtilities.updateComponentTreeUI(window);
                }
            }
        });
    }

    @Override
    public int hashCode() {
        return this.brightnessOffset + this.hueOffset + this.saturationOffset;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof GhidorahTheme)) {
            return false;
        }
        GhidorahTheme other = (GhidorahTheme) obj;
        if (other.brightnessOffset != this.brightnessOffset) {
            return false;
        }
        if (other.hueOffset != this.hueOffset) {
            return false;
        }
        return other.saturationOffset == this.saturationOffset;
    }

    @Override
    public String toString() {
        return getClass().getName() + "(" + this.hueOffset + "," + this.saturationOffset + "," + this.brightnessOffset + ")";
    }

}
