package ghidorah;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSlider;
import javax.swing.JTextArea;
import javax.swing.LookAndFeel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.plaf.metal.MetalLookAndFeel;
import javax.swing.plaf.metal.MetalTheme;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.*;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.task.TaskMonitor;
import docking.ComponentProvider;
import docking.widgets.table.GFilterTable;
import ghidra.app.services.GoToService;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.table.GhidraTable;

/**
 * @author quosego
 *
 */
public class GhidorahProvider extends ComponentProvider {
	private static final String PROVIDER_TITLE = "Ghidorah - Color Plugin";
	
	private GhidorahPlugin plugin;
	
	private JPanel panelWindow;
	
	private JSlider sliderHue;
	private JSlider sliderSaturation;
	private JSlider sliderBrightness;
	
	private JLabel labelMessage;
	
	private JButton buttonDefault;
	private JButton buttonOkay;
	private JButton buttonCancel;

	private Thread threadTheme;
	
	private LookAndFeel themeLookAndFeel;
	private MetalTheme themeMetal;
	
	protected Boolean updateRequest;
	protected Boolean updateAccept;

	public GhidorahProvider(GhidorahPlugin plugin) {
		super(plugin.getTool(), PROVIDER_TITLE, plugin.getName());
		
		this.plugin = plugin;
		
		this.updateRequest = false;
		this.updateAccept = false;
		
		build();
		listeners();
		startup();
	}
	
	private void build() {
		this.panelWindow = new JPanel(new BorderLayout());
		this.panelWindow.add(buildControlPanel(), BorderLayout.CENTER);
		this.panelWindow.setVisible(true);
		setVisible(true);
	}
	
	private void listeners() {
		this.sliderHue.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent e) {
				onSliderValueChanged();
			}
		});
		this.sliderSaturation.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent e) {
				onSliderValueChanged();
			}
		});
		this.sliderBrightness.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent e) {
				onSliderValueChanged();
			}
		});
		
		this.buttonOkay.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				onButtonOkay();
			}
		});
		this.buttonDefault.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				onButtonDefault();
			}
		});
		this.buttonCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				onButtonCancel();
			}
		});
	}
	
	private Component buildControlPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBounds(100, 100, 450, 300);
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		
		JPanel panelMessage = new JPanel();
		
		this.labelMessage = new JLabel("Change the Colors: ");
		this.labelMessage.setHorizontalAlignment(SwingConstants.CENTER);
		
		panelMessage.add(this.labelMessage);
		panel.add(panelMessage, BorderLayout.NORTH);
		
		JPanel panelSliders = new JPanel();
		
		this.sliderHue = new JSlider();
		this.sliderSaturation = new JSlider();
		this.sliderBrightness = new JSlider();
		this.sliderHue.setMaximum(255);
		this.sliderSaturation.setMaximum(255);
		this.sliderBrightness.setMaximum(255);
		
		panelSliders.add(this.sliderHue);
		panelSliders.add(this.sliderSaturation);
		panelSliders.add(this.sliderBrightness);
		panel.add(panelSliders, BorderLayout.CENTER);
		
		JPanel panelButtons = new JPanel();
		panelButtons.setForeground(UIManager.getColor("ComboBox.selectionForeground"));
		panelButtons.setLayout(new FlowLayout(FlowLayout.RIGHT));
		
		this.buttonOkay = new JButton("OK");
		this.buttonDefault = new JButton("Restore Defaults");
		this.buttonCancel = new JButton("Cancel");
		
		panelButtons.add(this.buttonOkay);
		panelButtons.add(this.buttonDefault);
		panelButtons.add(this.buttonCancel);
		panel.add(panelButtons, BorderLayout.SOUTH);
		
		return panel;
	}
	
	private void startup() {
		setupTheme(getSelectedTheme());
		startThemeUpdate();
	}
	
	public void dispose() {
		stopThemeUpdate();
		if (!updateAccept) {
			restoreTheme();
		}
		setVisible(false);
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return this.panelWindow;
	}
	
	//
	
	private void setupTheme(GhidorahTheme theme) {
		this.themeLookAndFeel = UIManager.getLookAndFeel();
		this.themeMetal = MetalLookAndFeel.getCurrentTheme();
		if (this.themeLookAndFeel != null) {
			this.sliderHue.setValue(theme.getHueOffset());
			this.sliderSaturation.setValue(theme.getSaturationOffset());
			this.sliderBrightness.setValue(theme.getBrightnessOffset());
		} else {
			this.sliderHue.setValue(GhidorahTheme.getDefaultHueOffset());
			this.sliderSaturation.setValue(GhidorahTheme.getDefaultSaturationOffset());
			this.sliderBrightness.setValue(GhidorahTheme.getDefaultBrightnessOffset());
		}
	}
	
	private void restoreTheme() {
		try {
			MetalLookAndFeel.setCurrentTheme(this.themeMetal);
			UIManager.setLookAndFeel(this.themeLookAndFeel);
			for (Window window : Window.getWindows()) {
				SwingUtilities.updateComponentTreeUI(window);
			}
		} catch (UnsupportedLookAndFeelException e) {
			throw new AssertionError(e);
		}
	}
	
	//
	
	private GhidorahTheme getSelectedTheme() {
		return new GhidorahTheme(this.sliderHue.getValue(), this.sliderSaturation.getValue(), this.sliderBrightness.getValue());
	}
	
	private void setSelectedTheme(GhidorahTheme theme) {
		this.sliderHue.setValue(theme.getHueOffset());
		this.sliderSaturation.setValue(theme.getSaturationOffset());
		this.sliderBrightness.setValue(theme.getBrightnessOffset());
	}
	
	//
	
	private void onThemeUpdate() {
		GhidorahTheme theme = getSelectedTheme();
		theme.activate();
		this.labelMessage.setForeground(UIManager.getColor("Label.background"));
		this.labelMessage.setBackground(UIManager.getColor("Label.foreground"));
	}
	
	private void onColorUpdate() {
		this.sliderHue.setBorder(BorderFactory.createTitledBorder("Hue: " + sliderHue.getValue()));
		this.sliderSaturation.setBorder(BorderFactory.createTitledBorder("Saturation: " + sliderSaturation.getValue()));
		this.sliderBrightness.setBorder(BorderFactory.createTitledBorder("Brightness: " + sliderBrightness.getValue()));
	}
	
	private void onSliderValueChanged() {
		onColorUpdate();
		this.updateRequest = true;
	}
	
	private void onButtonOkay() {
		this.updateAccept = true;
		dispose();
	}
	
	private void onButtonDefault() {
		setSelectedTheme(new GhidorahTheme(GhidorahTheme.getDefaultHueOffset(), GhidorahTheme.getDefaultSaturationOffset(), GhidorahTheme.getDefaultBrightnessOffset()));
		dispose();
	}
	
	private void onButtonCancel() {
		this.updateAccept = false;
		dispose();
	}
	
	//
	
	private void startThemeUpdate() {
		threadTheme = new Thread(GhidorahProvider.class.getName() + " - ThemeUpdater") {
			@Override
			public void run() {
				while (true) {
					try {
						if (isInterrupted()) {
							break;
						}
						if (updateRequest) {
							updateRequest = false;
							SwingUtilities.invokeAndWait(new Runnable() {
								@Override
								public void run() {
									onThemeUpdate();
								}
							});
						} else {
							// wait here
							sleep(1200);
						}
					} catch (InterruptedException e) {
						interrupt();
					} catch (Throwable t) {
						t.printStackTrace();
					}
				}
			}
		};
		threadTheme.setDaemon(true);
		threadTheme.setPriority(Thread.MIN_PRIORITY);
		threadTheme.start();
	}
	
	private void stopThemeUpdate() {
		threadTheme.interrupt();
		try {
			threadTheme.join();
		} catch (InterruptedException e) {
			throw new AssertionError(e);
		}	
	}
}
