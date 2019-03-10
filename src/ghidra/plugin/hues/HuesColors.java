package ghidra.plugin.hues;

import javax.swing.plaf.ColorUIResource;
import javax.swing.plaf.metal.DefaultMetalTheme;
import java.awt.*;

/**
 * @author quosego <https://github.com/quosego>
 * @version Mar 9, 2019
 */
public class HuesColors {
    private float brightness;
    private float saturation;
    private float hue;

    public HuesColors(float brightness, float saturation, float hue) {
        setColor(brightness, saturation, hue);
    }

    public HuesColors(Color color) {
        setColor(color);
    }

    public HuesColors() {
        this(0, 0, 0);
    }

    public float getBrightness() {
        return brightness;
    }

    public void setBrightness(float brightness) {
        this.brightness = brightness;
    }

    public float getSaturation() {
        return saturation;
    }

    public void setSaturation(float saturation) {
        this.saturation = saturation;
    }

    public float getHue() {
        return hue;
    }

    public void setHue(float hue) {
        this.hue = hue;
    }

    private float adjustColorOverflow(float value) {
        if (value < 0.0) {
            return adjustColorOverflow(-value);
        }
        if (value > 1.0) {
            return adjustColorOverflow((float) Math.ceil(value) - value);
        }
        return Math.round(value * 100f) / 100f;
    }

    public ColorUIResource changeColorResource(Color color, HuesColors other) {
        float[] hsb = Color.RGBtoHSB(color.getRed(), color.getGreen(), color.getBlue(), null);

        hsb[0] = adjustColorOverflow(hsb[0] - this.getHue() + (other.getHue() / 255f));
        hsb[1] = adjustColorOverflow(hsb[1] - this.getSaturation() + (other.getSaturation() / 255f));
        hsb[2] = adjustColorOverflow(hsb[2] - this.getBrightness() + (other.getBrightness() / 255f));

        return new ColorUIResource(Color.HSBtoRGB(hsb[0], hsb[1], hsb[2]));
    }

    public Color getColor() {
        return Color.getHSBColor(this.hue, this.saturation, this.brightness);
    }

    public void setColor(DefaultMetalTheme theme) {
        ColorUIResource resource = theme.getControl();
        setColor(resource);
    }

    public void setColor(Color color) {
        float[] offsets = Color.RGBtoHSB(color.getRed(), color.getGreen(), color.getBlue(), null);
        setColor(
                Math.round(offsets[2]), Math.round(offsets[1]), Math.round(offsets[0]));
    }

    public void setColor(float brightness, float saturation, float hue) {
        setBrightness(brightness);
        setSaturation(saturation);
        setHue(hue);
    }

    @Override
    public int hashCode() {
        return (int) this.getHue() + (int) this.getSaturation() + (int) this.getBrightness();
    }

    @Override
    public boolean equals(Object obj) {
        if ((obj instanceof HuesColors)) {
            HuesColors other = (HuesColors) obj;
            if (other != null) {
                if (other.getBrightness() != this.getBrightness()) {
                    return false;
                } else if (other.getSaturation() != this.getSaturation()) {
                    return false;
                } else if (other.getHue() != this.getHue()) {
                    return false;
                } else {
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
                + ": { hue: "
                + this.getHue()
                + ", saturation: "
                + this.getSaturation()
                + ", brightness: "
                + this.getBrightness()
                + "}}";
    }
}
