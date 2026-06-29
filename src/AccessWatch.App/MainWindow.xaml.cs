using System.Windows;
using AccessWatch.App.ViewModels;

namespace AccessWatch.App;

/// <summary>
/// Interaction logic for the AccessWatch dashboard window.
/// </summary>
public partial class MainWindow : Window
{
    /// <summary>
    /// Initializes the dashboard shell window.
    /// </summary>
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new DashboardShellViewModel();
    }
}
