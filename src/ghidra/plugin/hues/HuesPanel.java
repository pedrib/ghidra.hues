package ghidra.plugin.hues;

import ghidra.framework.preferences.Preferences;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * @author quosego <https://github.com/quosego>
 * @version Mar 9, 2019
 */
public class HuesPanel {
    public static final String HUES_COLORS_KEY = "Hues.Default";
    public static final String HUES_PROFILE1_KEY = "Hues.Profile1";
    public static final String HUES_PROFILE2_KEY = "Hues.Profile2";
    public static final String HUES_PROFILE3_KEY = "Hues.Profile3";
    public static final String HUES_PROFILE4_KEY = "Hues.Profile4";
    public static final String HUES_PROFILE5_KEY = "Hues.Profile5";
    private JPanel panelWindow;
    private JSlider sliderHues;
    private JSlider sliderBrightness;
    private JSlider sliderSaturation;
    protected JComboBox comboProfiles;
    private JButton buttonSet;
    private JButton buttonSave;
    private JLabel labelHue;
    private JLabel labelSaturation;
    private JLabel labelBrightness;
    private JLabel labelProfiles;
    protected Thread threadHues;
    protected boolean statusHues;

    public HuesPanel() {
        build();
        listeners();
        setup();
    }

    // ==================================================================================================
    // Panel Bridge methods
    // ==================================================================================================

    public JComponent getHuesPanel() {
        return this.panelWindow;
    }

    // ==================================================================================================
    // Panel Setup methods
    // ==================================================================================================

    private void build() {
        panelWindow = new JPanel();
        panelWindow.setLayout(new BorderLayout(0, 0));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(
                new com.intellij.uiDesigner.core.GridLayoutManager(10, 1, new Insets(0, 0, 0, 0), -1, -1));
        panelWindow.add(panel1, BorderLayout.CENTER);
        //
        final com.intellij.uiDesigner.core.Spacer spacer1 = new com.intellij.uiDesigner.core.Spacer();
        panel1.add(
                spacer1,
                new com.intellij.uiDesigner.core.GridConstraints(
                        1,
                        0,
                        1,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW,
                        null,
                        null,
                        null,
                        0,
                        false));
        //
        final JPanel panel2 = new JPanel();
        final com.intellij.uiDesigner.core.Spacer spacer2 = new com.intellij.uiDesigner.core.Spacer();
        panel2.add(
                spacer2,
                new com.intellij.uiDesigner.core.GridConstraints(
                        0,
                        0,
                        1,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW,
                        null,
                        null,
                        null,
                        0,
                        false));
        labelProfiles = new JLabel();
        labelProfiles.setText("Profiles:");
        panel2.add(
                labelProfiles,
                new com.intellij.uiDesigner.core.GridConstraints(
                        1,
                        0,
                        1,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        null,
                        null,
                        null,
                        0,
                        false));
        panel2.setLayout(
                new com.intellij.uiDesigner.core.GridLayoutManager(3, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(
                panel2,
                new com.intellij.uiDesigner.core.GridConstraints(
                        0,
                        0,
                        1,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        null,
                        null,
                        null,
                        0,
                        false));
        comboProfiles = new JComboBox();
        this.comboProfiles.addItem("Profile 1");
        this.comboProfiles.addItem("Profile 2");
        this.comboProfiles.addItem("Profile 3");
        this.comboProfiles.addItem("Profile 4");
        this.comboProfiles.addItem("Profile 5");
        this.comboProfiles.setSelectedIndex(0);
        panel2.add(
                comboProfiles,
                new com.intellij.uiDesigner.core.GridConstraints(
                        2,
                        0,
                        1,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        null,
                        null,
                        null,
                        0,
                        false));
        //
        labelHue = new JLabel();
        labelHue.setText("Hue: 0");
        panel1.add(
                labelHue,
                new com.intellij.uiDesigner.core.GridConstraints(
                        2,
                        0,
                        1,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        null,
                        null,
                        null,
                        0,
                        false));
        labelSaturation = new JLabel();
        labelSaturation.setText("Saturation: 0");
        panel1.add(
                labelSaturation,
                new com.intellij.uiDesigner.core.GridConstraints(
                        4,
                        0,
                        1,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        null,
                        null,
                        null,
                        0,
                        false));
        labelBrightness = new JLabel();
        labelBrightness.setText("Brightness: 0");
        panel1.add(
                labelBrightness,
                new com.intellij.uiDesigner.core.GridConstraints(
                        6,
                        0,
                        1,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        null,
                        null,
                        null,
                        0,
                        false));
        //
        final com.intellij.uiDesigner.core.Spacer spacer3 = new com.intellij.uiDesigner.core.Spacer();
        panel1.add(
                spacer3,
                new com.intellij.uiDesigner.core.GridConstraints(
                        8,
                        0,
                        1,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW,
                        null,
                        null,
                        null,
                        0,
                        false));
        //
        sliderSaturation = new JSlider();
        sliderSaturation.setMaximum(255);
        panel1.add(
                sliderSaturation,
                new com.intellij.uiDesigner.core.GridConstraints(
                        5,
                        0,
                        1,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        null,
                        null,
                        null,
                        0,
                        false));
        sliderHues = new JSlider();
        sliderHues.setMaximum(255);
        panel1.add(
                sliderHues,
                new com.intellij.uiDesigner.core.GridConstraints(
                        3,
                        0,
                        1,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        null,
                        null,
                        null,
                        0,
                        false));
        sliderBrightness = new JSlider();
        sliderBrightness.setMaximum(255);
        panel1.add(
                sliderBrightness,
                new com.intellij.uiDesigner.core.GridConstraints(
                        7,
                        0,
                        1,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        null,
                        null,
                        null,
                        0,
                        false));
        //
        final JPanel panel3 = new JPanel();
        panel3.setLayout(
                new com.intellij.uiDesigner.core.GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        buttonSet = new JButton();
        buttonSet.setText("Set as Default");
        panel3.add(
                buttonSet,
                new com.intellij.uiDesigner.core.GridConstraints(
                        0,
                        0,
                        1,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        null,
                        null,
                        null,
                        0,
                        false));
        buttonSave = new JButton();
        buttonSave.setText("Save");
        panel3.add(
                buttonSave,
                new com.intellij.uiDesigner.core.GridConstraints(
                        0,
                        1,
                        1,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        null,
                        null,
                        null,
                        0,
                        false));
        panel1.add(
                panel3,
                new com.intellij.uiDesigner.core.GridConstraints(
                        9,
                        0,
                        1,
                        1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        null,
                        null,
                        null,
                        0,
                        false));
    }

    private void listeners() {
        this.sliderHues.addChangeListener(
                new ChangeListener() {
                    public void stateChanged(ChangeEvent e) {
                        onSliderValueChanged();
                    }
                });
        this.sliderSaturation.addChangeListener(
                new ChangeListener() {
                    public void stateChanged(ChangeEvent e) {
                        onSliderValueChanged();
                    }
                });
        this.sliderBrightness.addChangeListener(
                new ChangeListener() {
                    public void stateChanged(ChangeEvent e) {
                        onSliderValueChanged();
                    }
                });

        this.buttonSet.addActionListener(
                new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        onButtonSet();
                    }
                });
        this.buttonSave.addActionListener(
                new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        onButtonSave();
                    }
                });
        this.comboProfiles.addActionListener(
                new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        loadProfile(comboProfiles.getSelectedItem().toString());
                    }
                });
    }

    private void setup() {
        this.statusHues = false;
        Hues t = new Hues();
        HuesColors hue = t.getDefaultHueColors();
        this.sliderHues.setValue((int) hue.getHue());
        this.sliderSaturation.setValue((int) hue.getSaturation());
        this.sliderBrightness.setValue((int) hue.getBrightness());
        onColorUpdate();
        startUIMonitor();
        getDefault();
    }

    public void close() {
        stopUIMonitor();
    }

    // ==================================================================================================
    // Listener Action methods
    // ==================================================================================================

    private void onColorUpdate() {
        this.labelHue.setText("Hue: " + sliderHues.getValue());
        this.labelSaturation.setText("Saturation: " + sliderSaturation.getValue());
        this.labelBrightness.setText("Brightness: " + sliderBrightness.getValue());
    }

    private void onSliderValueChanged() {
        onColorUpdate();
        this.statusHues = true;
    }

    private void onButtonSet() {
        setDefault();
    }

    private void onButtonSave() {
        saveProfile(comboProfiles.getSelectedItem().toString());
    }

    // ==================================================================================================
    // Hue Profile methods
    // ==================================================================================================

    private void setDefault() {
        Preferences.setProperty(
                HUES_COLORS_KEY,
                ""
                        + String.valueOf(sliderHues.getValue()).replaceAll("\\s+", "")
                        + ","
                        + String.valueOf(sliderSaturation.getValue()).replaceAll("\\s+", "")
                        + ", "
                        + String.valueOf(sliderBrightness.getValue()).replaceAll("\\s+", ""));
        Preferences.store();
    }

    private void getDefault() {
        try {
            String value = Preferences.getProperty(HUES_COLORS_KEY);
            String[] defaults = value.split(",");
            if (defaults.length != 3) {
                throw new Exception("");
            }
        } catch (Exception e) {
            Preferences.setProperty(HUES_COLORS_KEY, "0,0,255");
            Preferences.store();
        } finally {
            String value = Preferences.getProperty(HUES_COLORS_KEY);
            String[] defaults = value.split(",");

            sliderHues.setValue(Integer.parseInt(defaults[0].replaceAll("\\s+", "")));
            sliderSaturation.setValue(Integer.parseInt(defaults[1].replaceAll("\\s+", "")));
            sliderBrightness.setValue(Integer.parseInt(defaults[2].replaceAll("\\s+", "")));
        }
    }

    private void getProfile(String profileKey) {
        try {
            String value = Preferences.getProperty(profileKey);
            String[] defaults = value.split(",");
            if (defaults.length != 3) {
                throw new Exception("");
            }
        } catch (Exception e) {
            Preferences.setProperty(profileKey, "0,0,255");
            Preferences.store();
        } finally {
            String value = Preferences.getProperty(profileKey);
            String[] defaults = value.split(",");

            sliderHues.setValue(Integer.parseInt(defaults[0].replaceAll("\\s+", "")));
            sliderSaturation.setValue(Integer.parseInt(defaults[1].replaceAll("\\s+", "")));
            sliderBrightness.setValue(Integer.parseInt(defaults[2].replaceAll("\\s+", "")));
        }
    }

    private void setProfile(String profileKey) {
        Preferences.setProperty(
                profileKey,
                ""
                        + String.valueOf(sliderHues.getValue()).replaceAll("\\s+", "")
                        + ","
                        + String.valueOf(sliderSaturation.getValue()).replaceAll("\\s+", "")
                        + ", "
                        + String.valueOf(sliderBrightness.getValue()).replaceAll("\\s+", ""));
        Preferences.store();
    }

    private void loadProfile(String profileName) {
        int profile = Integer.parseInt(profileName.substring(profileName.length() - 1));

        switch (profile) {
            case 1:
                getProfile(HUES_PROFILE1_KEY);
                break;
            case 2:
                getProfile(HUES_PROFILE2_KEY);
                break;
            case 3:
                getProfile(HUES_PROFILE3_KEY);
                break;
            case 4:
                getProfile(HUES_PROFILE4_KEY);
                break;
            case 5:
                getProfile(HUES_PROFILE5_KEY);
                break;
            default:
                break;
        }
    }

    private void saveProfile(String profileName) {
        int profile = Integer.parseInt(profileName.substring(profileName.length() - 1));

        switch (profile) {
            case 1:
                setProfile(HUES_PROFILE1_KEY);
                break;
            case 2:
                setProfile(HUES_PROFILE2_KEY);
                break;
            case 3:
                setProfile(HUES_PROFILE3_KEY);
                break;
            case 4:
                setProfile(HUES_PROFILE4_KEY);
                break;
            case 5:
                setProfile(HUES_PROFILE5_KEY);
                break;
            default:
                break;
        }
    }

    // ==================================================================================================
    // Hue Change methods
    // ==================================================================================================

    private void onThemeUpdate() {
        Hues t =
                new Hues(sliderBrightness.getValue(), sliderSaturation.getValue(), sliderHues.getValue());
        t.activate();
    }

    private void startUIMonitor() {
        threadHues =
                new Thread(HuesPanel.class.getName() + ".slider") {
                    @SuppressWarnings("static-access")
                    @Override
                    public void run() {
                        while (true) {
                            try {
                                if (isInterrupted()) {
                                    break;
                                }
                                if (statusHues) {
                                    statusHues = false;
                                    SwingUtilities.invokeAndWait(
                                            new Runnable() {
                                                @Override
                                                public void run() {
                                                    onThemeUpdate();
                                                }
                                            });
                                } else {
                                    // wait here
                                    threadHues.sleep(2000);
                                }
                            } catch (InterruptedException e) {
                                interrupt();
                            } catch (Throwable t) {
                                interrupt();
                            }
                        }
                    }
                };
        threadHues.setDaemon(true);
        threadHues.setPriority(Thread.MIN_PRIORITY);
        threadHues.start();
    }

    private void stopUIMonitor() {
        threadHues.interrupt();
        try {
            threadHues.join();
        } catch (InterruptedException e) {
            throw new AssertionError(e);
        }
    }
}
