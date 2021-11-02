import pandas as pd
import matplotlib.pyplot as plt

#to create a dataframe pandas needs equal size of list as values
def normalize_list(FUNCTION_ATTACK):
    total_functions =[]
    for key,value in FUNCTION_ATTACK.items():
        total_functions.append(len(value))
    max_f_count = max(total_functions)

    for key,value in FUNCTION_ATTACK.items():
        total_function = len(value)
        if total_function  < max_f_count:
            fill_up = ['*' for item in range(max_f_count-total_function)]
            FUNCTION_ATTACK[key] = FUNCTION_ATTACK[key] + fill_up
    return FUNCTION_ATTACK


def mapping2pdf(mapping,filename):
    df = pd.DataFrame.from_dict(mapping)
    fig, ax = plt.subplots()
    # hide axes
    fig.patch.set_visible(False)
    ax.axis('off')
    ax.axis('tight')
    ax.table(cellText=df.values, colLabels=df.columns.str.capitalize(), loc='center')
    plt.rc('font', size=18)
    #[Todo:] need to clean the filename
    plt.savefig(filename+'.png', dpi=300, bbox_inches='tight')
